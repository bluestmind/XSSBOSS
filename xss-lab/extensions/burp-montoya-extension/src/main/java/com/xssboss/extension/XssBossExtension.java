package com.xssboss.extension;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonParser;

import javax.swing.*;
import java.awt.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;

public class XssBossExtension implements BurpExtension, HttpHandler, ContextMenuItemsProvider {

    private MontoyaApi api;
    private Logging logging;
    private HttpClient httpClient;
    private ExecutorService executor;

    // Settings
    private String xssBossUrl = "http://localhost:8000";
    private int targetId = 1;
    private boolean syncEnabled = true;

    // Collaborator
    private burp.api.montoya.collaborator.CollaboratorClient collaboratorClient;
    private String collaboratorPayload;

    // UI elements
    private JTextField urlField;
    private JTextField targetIdField;
    private JCheckBox enabledCheckbox;
    private JLabel statusLabel;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        this.httpClient = HttpClient.newBuilder().build();
        this.executor = Executors.newFixedThreadPool(4);

        api.extension().setName("XSS Boss Connector");
        logging.logToOutput("XSS Boss Connector initialized successfully.");

        // Register HTTP handler to capture proxy traffic
        api.http().registerHttpHandler(this);

        // Register custom settings tab in Burp UI
        api.userInterface().registerSuiteTab("XSS Boss", createSettingsTab());

        // Register Context Menu Provider to allow right-click direct fuzzing
        api.userInterface().registerContextMenuItemsProvider(this);

        // Start background polling thread for Repeater queue
        startRepeaterQueuePoller();

        // Start background polling thread for Findings/Issues dashboard sync
        startFindingsQueuePoller();

        // Initialize Collaborator client if supported by licensing/Burp version
        try {
            this.collaboratorClient = api.collaborator().createClient();
            this.collaboratorPayload = collaboratorClient.generatePayload().toString();
            logging.logToOutput("XSS Boss Collaborator base payload generated: " + collaboratorPayload);
            registerCollaborator(collaboratorPayload);
            startCollaboratorPoller();
        } catch (Exception e) {
            logging.logToError("Burp Collaborator is not available or licensed: " + e.getMessage());
        }
    }

    private Component createSettingsTab() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Title
        JLabel titleLabel = new JLabel("XSS Boss Integration Settings");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 16));
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        panel.add(titleLabel, gbc);

        gbc.gridwidth = 1;

        // API URL
        gbc.gridx = 0;
        gbc.gridy = 1;
        panel.add(new JLabel("XSS Boss API URL:"), gbc);
        
        urlField = new JTextField(xssBossUrl, 25);
        gbc.gridx = 1;
        panel.add(urlField, gbc);

        // Target ID
        gbc.gridx = 0;
        gbc.gridy = 2;
        panel.add(new JLabel("Active Target ID:"), gbc);

        targetIdField = new JTextField(String.valueOf(targetId), 10);
        gbc.gridx = 1;
        panel.add(targetIdField, gbc);

        // Enable Sync
        gbc.gridx = 0;
        gbc.gridy = 3;
        panel.add(new JLabel("Enable Real-time Sync:"), gbc);

        enabledCheckbox = new JCheckBox("", syncEnabled);
        gbc.gridx = 1;
        panel.add(enabledCheckbox, gbc);

        // Action Button
        JButton saveButton = new JButton("Save & Test Connection");
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.gridwidth = 2;
        panel.add(saveButton, gbc);

        // Status Label
        statusLabel = new JLabel("Status: Configured.");
        gbc.gridy = 5;
        panel.add(statusLabel, gbc);

        saveButton.addActionListener(e -> {
            try {
                xssBossUrl = urlField.getText().trim();
                targetId = Integer.parseInt(targetIdField.getText().trim());
                syncEnabled = enabledCheckbox.isSelected();
                statusLabel.setText("Saving settings...");
                
                testConnection();
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(panel, "Target ID must be a valid integer.", "Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        return panel;
    }

    private void testConnection() {
        executor.submit(() -> {
            try {
                java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                        .uri(URI.create(xssBossUrl + "/health"))
                        .GET()
                        .build();
                java.net.http.HttpResponse<String> response = httpClient.send(request, BodyHandlers.ofString());
                if (response.statusCode() == 200) {
                    SwingUtilities.invokeLater(() -> statusLabel.setText("Status: Connected to XSS Boss successfully!"));
                } else {
                    SwingUtilities.invokeLater(() -> statusLabel.setText("Status: Connection failed with code " + response.statusCode()));
                }
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> statusLabel.setText("Status: Connection failed: " + e.getMessage()));
            }
        });
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // Forward request & response to XSS Boss in background if enabled and in scope
        if (syncEnabled && api.scope().isInScope(responseReceived.initiatingRequest().url())) {
            executor.submit(() -> {
                sendToXssBoss(responseReceived.initiatingRequest(), responseReceived);
            });
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private void sendToXssBoss(HttpRequest request, HttpResponse response) {
        try {
            JsonObject json = new JsonObject();
            json.addProperty("target_id", targetId);
            json.addProperty("method", request.method());
            json.addProperty("url", request.url());
            
            // Map headers
            JsonObject reqHeaders = new JsonObject();
            request.headers().forEach(header -> {
                reqHeaders.addProperty(header.name(), header.value());
            });
            json.add("headers", reqHeaders);

            // Body
            json.addProperty("body", request.bodyToString());

            // Response
            if (response != null) {
                JsonObject respJson = new JsonObject();
                respJson.addProperty("status_code", response.statusCode());
                respJson.addProperty("body", response.bodyToString());
                json.add("response", respJson);
            }

            java.net.http.HttpRequest apiRequest = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(xssBossUrl + "/api/v1/burp/extension-push"))
                    .header("Content-Type", "application/json")
                    .POST(BodyPublishers.ofString(json.toString()))
                    .build();

            java.net.http.HttpResponse<String> apiResponse = httpClient.send(apiRequest, BodyHandlers.ofString());
            if (apiResponse.statusCode() != 200 && apiResponse.statusCode() != 201) {
                logging.logToError("Failed to sync request to XSS Boss. Status code: " + apiResponse.statusCode());
            }
        } catch (Exception e) {
            logging.logToError("Error syncing request to XSS Boss: " + e.getMessage());
        }
    }

    private void startRepeaterQueuePoller() {
        executor.submit(() -> {
            while (true) {
                try {
                    if (syncEnabled) {
                        pollRepeaterQueue();
                    }
                } catch (Exception e) {
                    logging.logToError("Error in repeater queue poller: " + e.getMessage());
                }
                try {
                    Thread.sleep(2000); // Poll every 2 seconds
                } catch (InterruptedException e) {
                    break;
                }
            }
        });
    }

    private void pollRepeaterQueue() {
        try {
            java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(xssBossUrl + "/api/v1/burp/repeater-queue"))
                    .GET()
                    .build();
            java.net.http.HttpResponse<String> response = httpClient.send(request, BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                String body = response.body();
                JsonArray array = JsonParser.parseString(body).getAsJsonArray();
                for (int i = 0; i < array.size(); i++) {
                    JsonObject obj = array.get(i).getAsJsonObject();
                    String host = obj.get("host").getAsString();
                    int port = obj.get("port").getAsInt();
                    boolean secure = obj.get("secure").getAsBoolean();
                    String rawRequest = obj.get("raw_request").getAsString();
                    String label = obj.get("label").getAsString();
                    String tool = obj.has("tool") ? obj.get("tool").getAsString() : "repeater";

                    // Reconstruct request inside Montoya
                    burp.api.montoya.http.HttpService service = burp.api.montoya.http.HttpService.httpService(host, port, secure);
                    burp.api.montoya.http.message.requests.HttpRequest montoyaRequest = burp.api.montoya.http.message.requests.HttpRequest.httpRequest(service, rawRequest);

                    // Send to designated Burp tool
                    if ("intruder".equalsIgnoreCase(tool)) {
                        api.intruder().sendToIntruder(montoyaRequest);
                        logging.logToOutput("Successfully sent request to Intruder: " + label);
                    } else {
                        api.repeater().sendToRepeater(montoyaRequest, label);
                        logging.logToOutput("Successfully sent request to Repeater: " + label);
                    }
                }
            }
        } catch (Exception e) {
            // Silently ignore connectivity issues when XSS Boss backend is offline
        }
    }

    @Override
    public java.util.List<Component> provideMenuItems(ContextMenuEvent event) {
        java.util.List<Component> items = new java.util.ArrayList<>();
        
        JMenuItem fuzzItem = new JMenuItem("Send to XSS Boss Fuzzer");
        fuzzItem.addActionListener(e -> {
            java.util.List<HttpRequestResponse> selected = event.selectedRequestResponses();
            if (selected != null && !selected.isEmpty()) {
                executor.submit(() -> {
                    for (HttpRequestResponse reqResp : selected) {
                        // 1. Push request to XSS Boss
                        sendToXssBoss(reqResp.request(), reqResp.response());
                        
                        // 2. Trigger active fuzzing for this target/endpoint immediately
                        triggerFuzzingForRequest(reqResp.request());
                    }
                });
            }
        });
        
        items.add(fuzzItem);
        return items;
    }

    private void triggerFuzzingForRequest(HttpRequest request) {
        try {
            // Step 1: Create experiment
            JsonObject createJson = new JsonObject();
            createJson.addProperty("target_id", targetId);
            createJson.addProperty("name", "Burp Direct Fuzz - " + request.url());
            createJson.addProperty("strategy", "genetic_evolutionary");
            createJson.add("limits", new JsonObject());

            java.net.http.HttpRequest apiRequest = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(xssBossUrl + "/api/v1/experiments/"))
                    .header("Content-Type", "application/json")
                    .POST(BodyPublishers.ofString(createJson.toString()))
                    .build();

            java.net.http.HttpResponse<String> apiResponse = httpClient.send(apiRequest, BodyHandlers.ofString());
            if (apiResponse.statusCode() == 201) {
                JsonObject expObj = JsonParser.parseString(apiResponse.body()).getAsJsonObject();
                int expId = expObj.get("id").getAsInt();
                
                // Step 2: Start experiment
                java.net.http.HttpRequest startRequest = java.net.http.HttpRequest.newBuilder()
                        .uri(URI.create(xssBossUrl + "/api/v1/experiments/" + expId + "/start"))
                        .POST(BodyPublishers.noBody())
                        .build();
                java.net.http.HttpResponse<String> startResponse = httpClient.send(startRequest, BodyHandlers.ofString());
                if (startResponse.statusCode() == 200) {
                    logging.logToOutput("Successfully triggered direct fuzzing experiment " + expId + " for " + request.url());
                } else {
                    logging.logToError("Failed to start direct fuzzing experiment: " + startResponse.statusCode());
                }
            } else {
                logging.logToError("Failed to create direct fuzzing experiment. Status code: " + apiResponse.statusCode());
            }
        } catch (Exception e) {
            logging.logToError("Error triggering direct fuzzing from Burp: " + e.getMessage());
        }
    }

    private void startFindingsQueuePoller() {
        executor.submit(() -> {
            while (true) {
                try {
                    if (syncEnabled) {
                        pollFindingsQueue();
                    }
                } catch (Exception e) {
                    logging.logToError("Error in findings queue poller: " + e.getMessage());
                }
                try {
                    Thread.sleep(2000); // Poll every 2 seconds
                } catch (InterruptedException e) {
                    break;
                }
            }
        });
    }

    private void pollFindingsQueue() {
        try {
            java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(xssBossUrl + "/api/v1/burp/findings-queue"))
                    .GET()
                    .build();
            java.net.http.HttpResponse<String> response = httpClient.send(request, BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                String body = response.body();
                JsonArray array = JsonParser.parseString(body).getAsJsonArray();
                for (int i = 0; i < array.size(); i++) {
                    JsonObject obj = array.get(i).getAsJsonObject();
                    String host = obj.get("host").getAsString();
                    int port = obj.get("port").getAsInt();
                    boolean secure = obj.get("secure").getAsBoolean();
                    String rawRequest = obj.get("raw_request").getAsString();
                    String rawResponse = obj.get("raw_response").getAsString();
                    
                    String name = obj.get("name").getAsString();
                    String detail = obj.get("detail").getAsString();
                    String remediation = obj.get("remediation").getAsString();
                    String url = obj.get("url").getAsString();
                    String severityStr = obj.get("severity").getAsString();
                    
                    String sinkType = obj.has("sink_type") ? obj.get("sink_type").getAsString() : "unknown";
                    String jsLocation = obj.has("js_location") ? obj.get("js_location").getAsString() : "unknown";
                    String notes = obj.has("notes") ? obj.get("notes").getAsString() : "";
                    
                    // Reconstruct request & response inside Montoya
                    burp.api.montoya.http.HttpService service = burp.api.montoya.http.HttpService.httpService(host, port, secure);
                    burp.api.montoya.http.message.requests.HttpRequest montoyaRequest = burp.api.montoya.http.message.requests.HttpRequest.httpRequest(service, rawRequest);
                    burp.api.montoya.http.message.responses.HttpResponse montoyaResponse = burp.api.montoya.http.message.responses.HttpResponse.httpResponse(rawResponse);
                    burp.api.montoya.http.message.HttpRequestResponse reqResp = burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(montoyaRequest, montoyaResponse);
                    
                    // Map severity
                    AuditIssueSeverity severity;
                    if ("critical".equalsIgnoreCase(severityStr) || "high".equalsIgnoreCase(severityStr)) {
                        severity = AuditIssueSeverity.HIGH;
                    } else if ("medium".equalsIgnoreCase(severityStr)) {
                        severity = AuditIssueSeverity.MEDIUM;
                    } else if ("low".equalsIgnoreCase(severityStr)) {
                        severity = AuditIssueSeverity.LOW;
                    } else {
                        severity = AuditIssueSeverity.INFORMATION;
                    }
                    
                    // Format html details with source to sink flow trace
                    String htmlDetail = formatHtmlDetail(detail, sinkType, jsLocation, notes);
                    
                    // Construct AuditIssue
                    AuditIssue issue = AuditIssue.auditIssue(
                        name,
                        htmlDetail,
                        remediation,
                        url,
                        severity,
                        AuditIssueConfidence.CERTAIN,
                        "Vulnerability identified dynamically via XSS Boss headless browser worker taint tracking and sink auditing.",
                        "Properly sanitize user-controlled parameters prior to passing to critical DOM sinks.",
                        severity,
                        java.util.List.of(reqResp)
                    );
                    
                    // Inject directly into Burp Suite Site Map & Issue list!
                    api.siteMap().add(issue);
                    logging.logToOutput("Successfully reported verified vulnerability to Burp Suite issues dashboard: " + name);
                }
            }
        } catch (Exception e) {
            // Silently ignore connectivity issues when XSS Boss backend is offline
        }
    }

    private String formatHtmlDetail(String reportText, String sinkType, String jsLocation, String notes) {
        StringBuilder sb = new StringBuilder();
        sb.append("<html><body>");
        
        sb.append("<h2 style='color:#ff5e5b;'>XSS Boss Active Headless Browser Verification Report</h2>");
        sb.append("<p>The fuzzer identified a fully exploitable client-side vulnerability. The browser instrumentation engine caught the exact taint flow and executed JavaScript code.</p>");
        
        sb.append("<h3 style='color:#00b4d8;'>Source-to-Sink Taint Flow:</h3>");
        sb.append("<table border='0' cellpadding='8' cellspacing='0' style='font-family:monospace; font-size:12px; background-color:#1e1e24; color:#f8f9fa; border-left:5px solid #ff5e5b; width:100%; border-radius:4px;'>");
        
        // Detect Source
        String source = "User-controlled input (HTTP Request Parameter)";
        if (notes != null) {
            if (notes.contains("__taint_loc_hash__") || notes.contains("location.hash")) {
                source = "DOM Source: location.hash (URL Fragment)";
            } else if (notes.contains("__taint_loc_search__") || notes.contains("location.search")) {
                source = "DOM Source: location.search (Query Parameter)";
            } else if (notes.contains("__taint_postmsg__") || notes.contains("postMessage")) {
                source = "DOM Source: Window postMessage Payload";
            } else if (notes.contains("cookie") || notes.contains("__taint_cookie__")) {
                source = "DOM Source: document.cookie";
            } else if (notes.contains("referrer") || notes.contains("__taint_referrer__")) {
                source = "DOM Source: document.referrer";
            }
        }
        
        sb.append("<tr><td><b style='color:#00f5d4;'>[SOURCE]</b> " + source + "</td></tr>");
        sb.append("<tr><td style='padding-left:25px; color:#a2a2a2;'>&nbsp;&nbsp;&nbsp;&nbsp;│ (Data propagates through client-side scripting)</td></tr>");
        sb.append("<tr><td style='padding-left:25px; color:#a2a2a2;'>&nbsp;&nbsp;&nbsp;&nbsp;▼</td></tr>");
        
        // Propagation / JS Location
        String locationStr = (jsLocation != null && !jsLocation.isEmpty()) ? jsLocation : "Dynamic execution context";
        sb.append("<tr><td><b style='color:#fee440;'>[PROPAGATION]</b> Code execution traced at: <code>" + locationStr + "</code></td></tr>");
        sb.append("<tr><td style='padding-left:25px; color:#a2a2a2;'>&nbsp;&nbsp;&nbsp;&nbsp;│ (Payload reaches dangerous sink unescaped)</td></tr>");
        sb.append("<tr><td style='padding-left:25px; color:#a2a2a2;'>&nbsp;&nbsp;&nbsp;&nbsp;▼</td></tr>");
        
        // Sink Type
        String sinkStr = (sinkType != null && !sinkType.isEmpty()) ? sinkType : "Execution callback";
        sb.append("<tr><td><b style='color:#ff5e5b;'>[SINK]</b> Dangerous DOM Sink Triggered: <code style='background-color:#3f37c9; padding:2px 4px; border-radius:3px; color:#ffffff;'>" + sinkStr + "</code></td></tr>");
        
        sb.append("</table>");
        
        // 2. Full Execution Trace and Stack
        if (notes != null && !notes.isEmpty()) {
            sb.append("<h3 style='color:#00b4d8;'>Dynamic Execution Stack Trace:</h3>");
            sb.append("<pre style='background-color:#2b2b2b; color:#a9b7c6; padding:10px; border-radius:4px; font-family:monospace; font-size:11px; overflow-x:auto;'>");
            sb.append(notes.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"));
            sb.append("</pre>");
        }
        
        // 3. Fuzzer Details
        sb.append("<h3 style='color:#00b4d8;'>Fuzzer Telemetry Summary:</h3>");
        if (reportText != null) {
            String formattedReport = reportText
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\n", "<br>")
                .replaceAll("\\*\\*([^\\*]+)\\*\\*", "<b>$1</b>")
                .replaceAll("`([^`]+)`", "<code>$1</code>");
            sb.append("<div style='font-family:sans-serif; font-size:12px; line-height:1.5;'>");
            sb.append(formattedReport);
            sb.append("</div>");
        }
        
        sb.append("</body></html>");
        return sb.toString();
    }

    private void registerCollaborator(String payload) {
        executor.submit(() -> {
            try {
                JsonObject json = new JsonObject();
                json.addProperty("payload", payload);
                java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                        .uri(URI.create(xssBossUrl + "/api/v1/burp/collaborator-register"))
                        .header("Content-Type", "application/json")
                        .POST(BodyPublishers.ofString(json.toString()))
                        .build();
                httpClient.send(request, BodyHandlers.ofString());
                logging.logToOutput("Successfully registered collaborator payload with XSS Boss backend.");
            } catch (Exception e) {
                logging.logToError("Failed to register collaborator payload: " + e.getMessage());
            }
        });
    }

    private void startCollaboratorPoller() {
        executor.submit(() -> {
            while (true) {
                try {
                    if (syncEnabled && collaboratorClient != null) {
                        pollCollaborator();
                    }
                } catch (Exception e) {
                    logging.logToError("Error in collaborator poller: " + e.getMessage());
                }
                try {
                    Thread.sleep(5000); // Poll every 5 seconds
                } catch (InterruptedException e) {
                    break;
                }
            }
        });
    }

    private void pollCollaborator() {
        try {
            java.util.List<burp.api.montoya.collaborator.Interaction> interactions = collaboratorClient.getAllInteractions();
            for (burp.api.montoya.collaborator.Interaction interaction : interactions) {
                java.util.Map<String, String> props = interaction.getProperties();
                String type = props.get("type");
                String clientIp = props.get("client_ip");
                String timestamp = props.get("time_stamp");
                String interactionId = props.get("interaction_id");
                
                String dnsQuery = props.get("raw_query");
                String httpRequest = props.get("request");
                
                // Try to extract token from host lookup or request path
                String token = null;
                
                if ("DNS".equalsIgnoreCase(type) && dnsQuery != null) {
                    byte[] decoded = java.util.Base64.getDecoder().decode(dnsQuery);
                    String decodedStr = new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
                    token = extractTestCaseId(decodedStr);
                } else if ("HTTP".equalsIgnoreCase(type) && httpRequest != null) {
                    byte[] decoded = java.util.Base64.getDecoder().decode(httpRequest);
                    String decodedStr = new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
                    token = extractTestCaseId(decodedStr);
                }
                
                // Report interaction back to XSS Boss
                JsonObject json = new JsonObject();
                json.addProperty("test_case_id", token != null ? token : "-1");
                json.addProperty("type", type);
                json.addProperty("client_ip", clientIp);
                json.addProperty("timestamp", timestamp);
                json.addProperty("interaction_id", interactionId);
                json.addProperty("raw_query", dnsQuery);
                json.addProperty("request", httpRequest);
                
                java.net.http.HttpRequest apiRequest = java.net.http.HttpRequest.newBuilder()
                        .uri(URI.create(xssBossUrl + "/api/v1/burp/collaborator-interaction"))
                        .header("Content-Type", "application/json")
                        .POST(BodyPublishers.ofString(json.toString()))
                        .build();
                java.net.http.HttpResponse<String> apiResponse = httpClient.send(apiRequest, BodyHandlers.ofString());
                if (apiResponse.statusCode() == 200) {
                    logging.logToOutput("Successfully reported collaborator interaction: " + interactionId + " (Matched token: " + token + ")");
                } else {
                    logging.logToError("Failed to report collaborator interaction. Status: " + apiResponse.statusCode());
                }
            }
        } catch (Exception e) {
            logging.logToError("Failed to poll collaborator interactions: " + e.getMessage());
        }
    }

    private String extractTestCaseId(String data) {
        if (data == null) return null;
        // Search for t[token] or tc=[token]
        // Since URL safe tokens can contain alphanumeric characters, dashes, and underscores (length 20 to 50)
        java.util.regex.Pattern p = java.util.regex.Pattern.compile("(?:t|tc=)([a-zA-Z0-9_-]{20,50})");
        java.util.regex.Matcher m = p.matcher(data);
        if (m.find()) {
            return m.group(1);
        }
        return null;
    }
}
