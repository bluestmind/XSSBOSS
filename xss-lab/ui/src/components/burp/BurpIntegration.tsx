/** Burp Suite Integration UI Component */
import React, { useState } from 'react';
import { burpApi } from '@/api/burp';

interface BurpIntegrationProps {
  targetId: number;
  targetUrl: string;
  onImportComplete?: () => void;
}

const BurpIntegration: React.FC<BurpIntegrationProps> = ({ targetId, targetUrl, onImportComplete }) => {
  const [activeTab, setActiveTab] = useState<'rest' | 'trigger' | 'xml' | 'montoya' | 'scans' | 'kb'>('rest');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Form states
  const [restUrl, setRestUrl] = useState('http://127.0.0.1:13337');
  const [restKey, setRestKey] = useState('');
  const [restTaskId, setRestTaskId] = useState('');
  
  const [scanUrls, setScanUrls] = useState(targetUrl);
  
  const [xmlFile, setXmlFile] = useState<File | null>(null);

  // Scan tasks & KB states
  const [scanTasks, setScanTasks] = useState<any[]>([]);
  const [issueDefinitions, setIssueDefinitions] = useState<any[]>([]);
  const [kbFilter, setKbFilter] = useState('');
  const [fetchingScans, setFetchingScans] = useState(false);
  const [fetchingKb, setFetchingKb] = useState(false);

  const normalizeTaskId = (value: string) => {
    const taskId = value.trim();
    if (!taskId) {
      throw new Error('Enter a Burp scan task ID first. Start a scan from the Trigger Scan tab if you do not have one yet.');
    }
    if (/^https?:\/\//i.test(taskId)) {
      throw new Error('The Burp Scan Task ID field contains a URL. Put http://127.0.0.1:13337 in the REST API URL field, and put only the scan task ID here.');
    }
    if (/[\\/]/.test(taskId)) {
      throw new Error('Burp scan task ID must be a single identifier, not a URL or path.');
    }
    return taskId;
  };

  const montoyaJavaCode = `package com.xssboss.extension;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
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

    private String xssBossUrl = "http://localhost:8000";
    private int targetId = ${targetId};
    private boolean syncEnabled = true;

    // Collaborator
    private burp.api.montoya.collaborator.CollaboratorClient collaboratorClient;
    private String collaboratorPayload;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        this.httpClient = HttpClient.newBuilder().build();
        this.executor = Executors.newFixedThreadPool(4);

        api.extension().setName("XSS Boss Connector");
        api.http().registerHttpHandler(this);
        api.userInterface().registerSuiteTab("XSS Boss", createSettingsTab());
        api.userInterface().registerContextMenuItemsProvider(this);

        // Start background pollers for repeater tasks and findings
        startRepeaterQueuePoller();
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

        JLabel titleLabel = new JLabel("XSS Boss Integration Settings");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 16));
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        panel.add(titleLabel, gbc);

        gbc.gridwidth = 1;
        gbc.gridx = 0; gbc.gridy = 1;
        panel.add(new JLabel("XSS Boss API URL:"), gbc);
        JTextField urlField = new JTextField(xssBossUrl, 25);
        gbc.gridx = 1;
        panel.add(urlField, gbc);

        gbc.gridx = 0; gbc.gridy = 2;
        panel.add(new JLabel("Active Target ID:"), gbc);
        JTextField targetIdField = new JTextField(String.valueOf(targetId), 10);
        gbc.gridx = 1;
        panel.add(targetIdField, gbc);

        gbc.gridx = 0; gbc.gridy = 3;
        panel.add(new JLabel("Enable Real-time Sync:"), gbc);
        JCheckBox enabledCheckbox = new JCheckBox("", syncEnabled);
        gbc.gridx = 1;
        panel.add(enabledCheckbox, gbc);

        JButton saveButton = new JButton("Save & Test Connection");
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2;
        panel.add(saveButton, gbc);

        saveButton.addActionListener(e -> {
            xssBossUrl = urlField.getText().trim();
            targetId = Integer.parseInt(targetIdField.getText().trim());
            syncEnabled = enabledCheckbox.isSelected();
            JOptionPane.showMessageDialog(panel, "Settings updated!");
        });

        return panel;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
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
            
            JsonObject reqHeaders = new JsonObject();
            request.headers().forEach(header -> reqHeaders.addProperty(header.name(), header.value()));
            json.add("headers", reqHeaders);
            json.addProperty("body", request.bodyToString());

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

            httpClient.send(apiRequest, BodyHandlers.ofString());
        } catch (Exception e) {
            logging.logToError("Error syncing request to XSS Boss: " + e.getMessage());
        }
    }

    private void startRepeaterQueuePoller() {
        executor.submit(() -> {
            while (true) {
                try {
                    if (syncEnabled) {
                        java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                                .uri(URI.create(xssBossUrl + "/api/v1/burp/repeater-queue"))
                                .GET()
                                .build();
                        java.net.http.HttpResponse<String> response = httpClient.send(request, BodyHandlers.ofString());
                        if (response.statusCode() == 200) {
                            JsonArray array = JsonParser.parseString(response.body()).getAsJsonArray();
                            for (int i = 0; i < array.size(); i++) {
                                JsonObject obj = array.get(i).getAsJsonObject();
                                String host = obj.get("host").getAsString();
                                int port = obj.get("port").getAsInt();
                                boolean secure = obj.get("secure").getAsBoolean();
                                String rawRequest = obj.get("raw_request").getAsString();
                                String label = obj.get("label").getAsString();
                                String tool = obj.has("tool") ? obj.get("tool").getAsString() : "repeater";

                                burp.api.montoya.http.HttpService service = burp.api.montoya.http.HttpService.httpService(host, port, secure);
                                burp.api.montoya.http.message.requests.HttpRequest montoyaRequest = burp.api.montoya.http.message.requests.HttpRequest.httpRequest(service, rawRequest);

                                if ("intruder".equalsIgnoreCase(tool)) {
                                    api.intruder().sendToIntruder(montoyaRequest);
                                } else {
                                    api.repeater().sendToRepeater(montoyaRequest, label);
                                }
                            }
                        }
                    }
                } catch (Exception e) {}
                try { Thread.sleep(2000); } catch (InterruptedException e) { break; }
            }
        });
    }

    private void startFindingsQueuePoller() {
        executor.submit(() -> {
            while (true) {
                try {
                    if (syncEnabled) {
                        java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                                .uri(URI.create(xssBossUrl + "/api/v1/burp/findings-queue"))
                                .GET()
                                .build();
                        java.net.http.HttpResponse<String> response = httpClient.send(request, BodyHandlers.ofString());
                        if (response.statusCode() == 200) {
                            JsonArray array = JsonParser.parseString(response.body()).getAsJsonArray();
                            for (int i = 0; i < array.size(); i++) {
                                JsonObject obj = array.get(i).getAsJsonObject();
                                String host = obj.get("host").getAsString();
                                int port = obj.get("port").getAsInt();
                                boolean secure = obj.get("secure").getAsBoolean();
                                String rawReq = obj.get("raw_request").getAsString();
                                String rawResp = obj.get("raw_response").getAsString();
                                String name = obj.get("name").getAsString();
                                String detail = obj.get("detail").getAsString();
                                String remediation = obj.get("remediation").getAsString();
                                String url = obj.get("url").getAsString();
                                String severityStr = obj.get("severity").getAsString();

                                burp.api.montoya.http.HttpService service = burp.api.montoya.http.HttpService.httpService(host, port, secure);
                                burp.api.montoya.http.message.requests.HttpRequest req = burp.api.montoya.http.message.requests.HttpRequest.httpRequest(service, rawReq);
                                burp.api.montoya.http.message.responses.HttpResponse resp = burp.api.montoya.http.message.responses.HttpResponse.httpResponse(rawResp);
                                HttpRequestResponse reqResp = HttpRequestResponse.httpRequestResponse(req, resp);

                                AuditIssueSeverity severity = AuditIssueSeverity.INFORMATION;
                                if ("high".equalsIgnoreCase(severityStr)) severity = AuditIssueSeverity.HIGH;
                                else if ("medium".equalsIgnoreCase(severityStr)) severity = AuditIssueSeverity.MEDIUM;
                                else if ("low".equalsIgnoreCase(severityStr)) severity = AuditIssueSeverity.LOW;

                                AuditIssue issue = AuditIssue.auditIssue(name, detail, remediation, url, severity, AuditIssueConfidence.CERTAIN, "Verified dynamically.", "Fix it.", severity, java.util.List.of(reqResp));
                                api.siteMap().add(issue);
                            }
                        }
                    }
                } catch (Exception e) {}
                try { Thread.sleep(2000); } catch (InterruptedException e) { break; }
            }
        });
    }

    @Override
    public java.util.List<Component> provideMenuItems(ContextMenuEvent event) {
        java.util.List<Component> items = new java.util.ArrayList<>();
        JMenuItem fuzzItem = new JMenuItem("Send to XSS Boss Fuzzer");
        fuzzItem.addActionListener(e -> {
            java.util.List<HttpRequestResponse> selected = event.selectedRequestResponses();
            if (selected != null) {
                executor.submit(() -> {
                    for (HttpRequestResponse reqResp : selected) {
                        sendToXssBoss(reqResp.request(), reqResp.response());
                    }
                });
            }
        });
        items.add(fuzzItem);
        return items;
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
                httpClient.send(apiRequest, BodyHandlers.ofString());
            }
        } catch (Exception e) {
            logging.logToError("Failed to poll collaborator interactions: " + e.getMessage());
        }
    }

    private String extractTestCaseId(String data) {
        if (data == null) return null;
        java.util.regex.Pattern p = java.util.regex.Pattern.compile("(?:t|tc=)([a-zA-Z0-9_-]{20,50})");
        java.util.regex.Matcher m = p.matcher(data);
        if (m.find()) {
            return m.group(1);
        }
        return null;
    }
}`;

  const montoyaGradleCode = `plugins {
    id 'java'
}

group 'com.xssboss'
version '1.0.0'

repositories {
    mavenCentral()
}

dependencies {
    compileOnly 'net.portswigger.burp.extensions:montoya-api:2023.12.1'
    implementation 'com.google.code.gson:gson:2.10.1'
}

jar {
    from {
        configurations.runtimeClasspath.collect { it.isDirectory() ? it : zipTree(it) }
    }
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    
    manifest {
        attributes(
            'Extension-Class': 'com.xssboss.extension.XssBossExtension',
            'Extension-Name': 'XSS Boss Connector',
            'Extension-Version': '1.0.0',
            'Extension-Description': 'Real-time proxy request sync with XSS Boss'
        )
    }
}`;

  const handleRestImport = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setMessage(null);
    try {
      const result = await burpApi.autoSync(targetId);
      const imported = result.sync?.imported_endpoints ?? 0;
      setMessage({
        type: 'success',
        text: `Burp scan launched and synced automatically. Task ${result.task_id}, imported ${imported} endpoint(s).`,
      });
      if (result.task_id) {
        setRestTaskId(result.task_id);
        setScanTasks((prev) => [
          { id: result.task_id, task_id: result.task_id, status: 'started' },
          ...prev.filter((task) => (task.id || task.task_id) !== result.task_id),
        ]);
      }
      if (onImportComplete) onImportComplete();
    } catch (err: any) {
      setMessage({
        type: 'error',
        text: err.response?.data?.detail || err.message || 'Failed to run automatic Burp sync. Ensure Burp REST API is running and the backend BURP_API_KEY matches Burp.',
      });
    } finally {
      setLoading(false);
    }
  };

  const handleTriggerScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setMessage(null);
    try {
      const urls = scanUrls.split('\n').map(u => u.trim()).filter(Boolean);
      if (urls.length === 0) {
        throw new Error('Please enter at least one URL to scan.');
      }
      const result = await burpApi.triggerScan(restUrl, urls, restKey);
      if (result.task_id) {
        setRestTaskId(result.task_id);
        setScanTasks((prev) => [
          { id: result.task_id, task_id: result.task_id, status: 'started' },
          ...prev.filter((task) => (task.id || task.task_id) !== result.task_id),
        ]);
      }
      setMessage({
        type: 'success',
        text: `Burp scan triggered successfully. Task ID: ${result.task_id || 'see Burp dashboard'}.`,
      });
    } catch (err: any) {
      setMessage({
        type: 'error',
        text: err.message || err.response?.data?.detail || 'Failed to trigger Burp Scan task.',
      });
    } finally {
      setLoading(false);
    }
  };

  const handleXmlImport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!xmlFile) {
      setMessage({ type: 'error', text: 'Please select a valid XML file to upload.' });
      return;
    }
    setLoading(true);
    setMessage(null);
    try {
      const result = await burpApi.uploadXml(targetId, xmlFile);
      setMessage({
        type: 'success',
        text: result.message || `XML file uploaded and successfully imported ${result.imported_count} endpoint(s).`,
      });
      if (onImportComplete) onImportComplete();
    } catch (err: any) {
      setMessage({
        type: 'error',
        text: err.response?.data?.detail || 'Failed to process uploaded Burp XML file.',
      });
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    alert('Code copied to clipboard!');
  };

  const fetchScans = async () => {
    setFetchingScans(true);
    setMessage(null);
    try {
      let taskId = '';
      try {
        taskId = normalizeTaskId(restTaskId);
      } catch (err: any) {
        setScanTasks([]);
        setMessage({
          type: 'error',
          text: err.message,
        });
        return;
      }
      const data = await burpApi.getScanTask(restUrl, taskId, restKey);
      setScanTasks([data]);
    } catch (err: any) {
      setMessage({
        type: 'error',
        text: err.response?.data?.detail || 'Failed to fetch active scan tasks from Burp REST API. Ensure the REST API service is running in Burp settings.',
      });
    } finally {
      setFetchingScans(false);
    }
  };

  const handleCancelScan = async (taskId: string) => {
    if (!window.confirm(`Are you sure you want to cancel and delete scan task ${taskId}?`)) {
      return;
    }
    setLoading(true);
    setMessage(null);
    try {
      await burpApi.cancelScanTask(restUrl, taskId, restKey);
      setMessage({
        type: 'success',
        text: `Successfully canceled scan task ${taskId}.`,
      });
      fetchScans();
    } catch (err: any) {
      setMessage({
        type: 'error',
        text: err.response?.data?.detail || `Failed to cancel scan task ${taskId}.`,
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchKb = async () => {
    setFetchingKb(true);
    setMessage(null);
    try {
      const data = await burpApi.getIssueDefinitions(restUrl, restKey);
      setIssueDefinitions(data);
    } catch (err: any) {
      setMessage({
        type: 'error',
        text: err.response?.data?.detail || 'Failed to fetch issue definitions from Burp REST API. Ensure the REST API service is running in Burp settings.',
      });
    } finally {
      setFetchingKb(false);
    }
  };

  return (
    <div className="bg-white rounded-lg border border-gray-200 shadow-sm overflow-hidden mb-6">
      <div className="border-b border-gray-200 bg-gray-50 px-6 py-4 flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold text-gray-900">Burp Suite Integration</h3>
          <p className="text-sm text-gray-500">Sync targets and endpoints automatically from your proxy or scan history.</p>
        </div>
        <div className="flex bg-gray-200 rounded-lg p-1">
          <button
            onClick={() => { setActiveTab('rest'); setMessage(null); }}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${activeTab === 'rest' ? 'bg-white text-gray-900 shadow' : 'text-gray-600 hover:text-gray-900'}`}
          >
            Auto Sync
          </button>
          <button
            onClick={() => { setActiveTab('xml'); setMessage(null); }}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${activeTab === 'xml' ? 'bg-white text-gray-900 shadow' : 'text-gray-600 hover:text-gray-900'}`}
          >
            XML Upload
          </button>
          <button
            onClick={() => { setActiveTab('montoya'); setMessage(null); }}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${activeTab === 'montoya' ? 'bg-white text-gray-900 shadow' : 'text-gray-600 hover:text-gray-900'}`}
          >
            Montoya Extension
          </button>
          <button
            onClick={() => { setActiveTab('kb'); setMessage(null); fetchKb(); }}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${activeTab === 'kb' ? 'bg-white text-gray-900 shadow' : 'text-gray-600 hover:text-gray-900'}`}
          >
            Knowledge Base
          </button>
        </div>
      </div>

      <div className="p-6">
        {message && (
          <div className={`mb-4 p-4 rounded-md text-sm ${message.type === 'success' ? 'bg-green-50 text-green-800 border border-green-200' : 'bg-red-50 text-red-800 border border-red-200'}`}>
            {message.text}
          </div>
        )}

        {/* REST API IMPORT */}
        {activeTab === 'rest' && (
          <form onSubmit={handleRestImport} className="space-y-4">
            <div className="bg-blue-50 border border-blue-200 text-blue-800 rounded p-4 text-xs leading-relaxed">
              <strong>Info:</strong> Starts a Burp scan for this target, captures the scan task internally, syncs available findings, and imports discovered endpoints.
            </div>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md text-sm font-semibold shadow-sm disabled:opacity-50"
            >
              {loading ? 'Running...' : 'Run Automatic Burp Sync'}
            </button>
          </form>
        )}

        {/* TRIGGER SCAN */}
        {activeTab === 'trigger' && (
          <form onSubmit={handleTriggerScan} className="space-y-4">
            <div className="bg-purple-50 border border-purple-200 text-purple-800 rounded p-4 text-xs leading-relaxed">
              <strong>Info:</strong> Initiate a Burp Suite crawler and scanner audit task for specific URLs. Burp Suite REST API must be enabled.
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-gray-700 uppercase mb-1">Burp REST API URL</label>
                <input
                  type="text"
                  value={restUrl}
                  onChange={(e) => setRestUrl(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 text-sm"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-gray-700 uppercase mb-1">REST API Key (Optional)</label>
                <input
                  type="password"
                  value={restKey}
                  onChange={(e) => setRestKey(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 text-sm"
                />
              </div>
            </div>
            <div>
              <label className="block text-xs font-semibold text-gray-700 uppercase mb-1">URLs to Audit (One per line)</label>
              <textarea
                value={scanUrls}
                onChange={(e) => setScanUrls(e.target.value)}
                rows={3}
                className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 text-sm font-mono"
                required
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-md text-sm font-semibold shadow-sm disabled:opacity-50"
            >
              {loading ? 'Triggering...' : 'Launch Burp Suite Scan'}
            </button>
          </form>
        )}

        {/* XML FILE UPLOAD */}
        {activeTab === 'xml' && (
          <form onSubmit={handleXmlImport} className="space-y-4">
            <div className="bg-yellow-50 border border-yellow-200 text-yellow-800 rounded p-4 text-xs leading-relaxed">
              <strong>Info:</strong> Export your scanned Sitemap or HTTP proxy history as an XML file from Burp Suite (make sure request and response base64 encoding is checked during export) and upload it here.
            </div>
            <div>
              <label className="block text-xs font-semibold text-gray-700 uppercase mb-1">Burp Export File (.xml)</label>
              <input
                type="file"
                accept=".xml"
                onChange={(e) => setXmlFile(e.target.files?.[0] || null)}
                className="w-full p-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 text-sm"
                required
              />
            </div>
            <button
              type="submit"
              disabled={loading || !xmlFile}
              className="px-4 py-2 bg-yellow-600 hover:bg-yellow-700 text-white rounded-md text-sm font-semibold shadow-sm disabled:opacity-50"
            >
              {loading ? 'Processing XML...' : 'Upload & Parse XML'}
            </button>
          </form>
        )}

        {/* MONTOYA EXTENSION */}
        {activeTab === 'montoya' && (
          <div className="space-y-4">
            <div className="bg-green-50 border border-green-200 text-green-800 rounded p-4 text-xs leading-relaxed">
              <strong>Live Telemetry Connector:</strong> Build and load this Montoya extension in Burp Suite. Every request inside Burp's target scope will automatically stream directly to XSS Boss in real time as you navigate or run scans!
            </div>
            
            <div className="space-y-4">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-semibold text-gray-800">1. src/main/java/com/xssboss/extension/XssBossExtension.java</span>
                  <button
                    onClick={() => copyToClipboard(montoyaJavaCode)}
                    className="px-3 py-1 bg-gray-100 hover:bg-gray-200 text-gray-800 text-xs font-medium rounded border border-gray-300"
                  >
                    Copy Java Code
                  </button>
                </div>
                <pre className="p-4 bg-gray-900 text-gray-100 rounded-md overflow-x-auto text-xs font-mono max-h-60">
                  {montoyaJavaCode}
                </pre>
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-semibold text-gray-800">2. build.gradle</span>
                  <button
                    onClick={() => copyToClipboard(montoyaGradleCode)}
                    className="px-3 py-1 bg-gray-100 hover:bg-gray-200 text-gray-800 text-xs font-medium rounded border border-gray-300"
                  >
                    Copy Gradle Config
                  </button>
                </div>
                <pre className="p-4 bg-gray-900 text-gray-100 rounded-md overflow-x-auto text-xs font-mono max-h-40">
                  {montoyaGradleCode}
                </pre>
              </div>

              <div className="text-xs text-gray-600 leading-relaxed pt-2">
                <strong>How to Load:</strong>
                <ol className="list-decimal pl-5 space-y-1 mt-1">
                  <li>Place files in a folder structure matching the packages.</li>
                  <li>Run <code className="bg-gray-100 px-1 py-0.5 rounded font-mono text-blue-700">gradle jar</code> inside the project root directory.</li>
                  <li>In Burp Suite, navigate to <strong>Extensions</strong> → <strong>Installed</strong> → <strong>Add</strong>.</li>
                  <li>Select Extension Type as <strong>Java</strong>, and upload the generated JAR file from <code className="bg-gray-100 px-1 py-0.5 rounded font-mono">build/libs/burp-montoya-extension-1.0.0.jar</code>.</li>
                  <li>Use the new <strong>XSS Boss</strong> tab inside Burp to manage real-time synchronization.</li>
                </ol>
              </div>
            </div>
          </div>
        )}

        {/* ACTIVE SCANS */}
        {activeTab === 'scans' && (
          <div className="space-y-4 animate-fadeIn">
            <div className="flex justify-between items-center bg-gray-50 border border-gray-200 rounded-lg p-4">
              <span className="text-xs text-gray-600">
                <strong>Active Scan Task:</strong> Burp Desktop REST API returns progress for a specific task ID. Enter a task ID or launch a scan, then refresh it here.
              </span>
              <button
                onClick={fetchScans}
                disabled={fetchingScans}
                className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs font-semibold shadow-sm flex items-center gap-1 disabled:opacity-50 transition-all"
              >
                {fetchingScans ? 'Refreshing...' : 'Refresh Tasks'}
              </button>
            </div>

            {fetchingScans ? (
              <div className="text-center py-8 text-sm text-gray-500">Loading scan tasks from Burp REST API...</div>
            ) : scanTasks.length === 0 ? (
              <div className="text-center py-8 text-sm text-gray-500 border border-dashed border-gray-300 rounded-lg">
                No task loaded. Use the <strong>Trigger Scan</strong> tab to start a task, or enter a task ID in the REST API Import tab.
              </div>
            ) : (
              <div className="border border-gray-200 rounded-lg overflow-hidden shadow-sm">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="bg-gray-50 border-b border-gray-200 text-gray-600 font-semibold uppercase tracking-wider">
                      <th className="px-4 py-3">Task ID</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Severity Breakdown</th>
                      <th className="px-4 py-3">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {scanTasks.map((task) => {
                      const id = task.id || task.task_id;
                      const rawStatus = task.status || task.scan_status?.status || task.scan_status?.type || task.scan_status || 'unknown';
                      const status = typeof rawStatus === 'string' ? rawStatus : 'unknown';
                      const isFinished = status === 'succeeded' || status === 'failed' || status === 'paused';
                      const issues = task.issue_events || task.issues || [];
                      const high = issues.filter((i: any) => i.severity?.toLowerCase() === 'high').length;
                      const medium = issues.filter((i: any) => i.severity?.toLowerCase() === 'medium').length;
                      const low = issues.filter((i: any) => i.severity?.toLowerCase() === 'low').length;
                      const info = issues.filter((i: any) => i.severity?.toLowerCase() === 'information' || i.severity?.toLowerCase() === 'info').length;

                      return (
                        <tr key={id} className="hover:bg-gray-50 transition-colors">
                          <td className="px-4 py-3 font-semibold text-gray-700">Task #{id}</td>
                          <td className="px-4 py-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                              status === 'succeeded' ? 'bg-green-100 text-green-800' :
                              status === 'running' ? 'bg-blue-100 text-blue-800 animate-pulse' :
                              status === 'failed' ? 'bg-red-100 text-red-800' : 'bg-gray-100 text-gray-800'
                            }`}>
                              {status}
                            </span>
                          </td>
                          <td className="px-4 py-3 flex gap-2">
                            {high > 0 && <span className="bg-red-100 text-red-800 font-semibold px-2 py-0.5 rounded text-[10px]">High: {high}</span>}
                            {medium > 0 && <span className="bg-orange-100 text-orange-800 font-semibold px-2 py-0.5 rounded text-[10px]">Med: {medium}</span>}
                            {low > 0 && <span className="bg-yellow-100 text-yellow-800 font-semibold px-2 py-0.5 rounded text-[10px]">Low: {low}</span>}
                            {info > 0 && <span className="bg-blue-100 text-blue-800 font-semibold px-2 py-0.5 rounded text-[10px]">Info: {info}</span>}
                            {high === 0 && medium === 0 && low === 0 && info === 0 && <span className="text-gray-400 italic">None reported</span>}
                          </td>
                          <td className="px-4 py-3 space-x-2">
                            <button
                              onClick={async () => {
                                setLoading(true);
                                try {
                                  setRestTaskId(id);
                                  await burpApi.importRest(targetId, restUrl, restKey, id);
                                  setMessage({ type: 'success', text: `Synced findings for task ${id}.` });
                                  if (onImportComplete) onImportComplete();
                                } catch (err) {
                                  alert('Could not sync findings: ' + err);
                                } finally {
                                  setLoading(false);
                                }
                              }}
                              className="px-2.5 py-1 text-[10px] bg-green-600 hover:bg-green-700 text-white font-semibold rounded-md shadow-sm transition-all"
                            >
                              Sync Findings
                            </button>
                            {!isFinished && (
                              <button
                                onClick={() => handleCancelScan(id)}
                                className="px-2.5 py-1 text-[10px] bg-red-600 hover:bg-red-700 text-white font-semibold rounded-md shadow-sm transition-all"
                              >
                                Cancel
                              </button>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* KNOWLEDGE BASE */}
        {activeTab === 'kb' && (
          <div className="space-y-4 animate-fadeIn">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center bg-gray-50 border border-gray-200 rounded-lg p-4 gap-3">
              <span className="text-xs text-gray-600">
                <strong>Burp Vulnerability Knowledge Base:</strong> Lists vulnerability issue types, descriptions, and severities defined inside Burp Suite.
              </span>
              <div className="flex gap-2 w-full md:w-auto">
                <input
                  type="text"
                  placeholder="Filter by issue type..."
                  value={kbFilter}
                  onChange={(e) => setKbFilter(e.target.value)}
                  className="px-3 py-1.5 border border-gray-300 rounded-md text-xs focus:ring-blue-500 focus:border-blue-500 w-full md:w-48 shadow-sm"
                />
                <button
                  onClick={fetchKb}
                  disabled={fetchingKb}
                  className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-md text-xs font-semibold shadow-sm disabled:opacity-50 transition-all whitespace-nowrap"
                >
                  {fetchingKb ? 'Refreshing...' : 'Refresh'}
                </button>
              </div>
            </div>

            {fetchingKb ? (
              <div className="text-center py-8 text-sm text-gray-500">Loading issue definitions from Burp REST API...</div>
            ) : issueDefinitions.length === 0 ? (
              <div className="text-center py-8 text-sm text-gray-500 border border-dashed border-gray-300 rounded-lg">
                No issue definitions found. Keep Burp Suite running.
              </div>
            ) : (
              <div className="border border-gray-200 rounded-lg overflow-hidden shadow-sm max-h-[500px] overflow-y-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead className="sticky top-0 bg-gray-50 border-b border-gray-200 text-gray-600 font-semibold uppercase tracking-wider z-10 shadow-sm">
                    <tr>
                      <th className="px-4 py-3 w-1/4">Issue Name</th>
                      <th className="px-4 py-3 w-1/6">Severity</th>
                      <th className="px-4 py-3">Description</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100 bg-white">
                    {issueDefinitions
                      .filter((def: any) => {
                        const name = def.name || def.issue_type || '';
                        return name.toLowerCase().includes(kbFilter.toLowerCase());
                      })
                      .map((def: any, index: number) => {
                        const severity = def.severity || 'unknown';
                        const name = def.name || def.issue_type || 'Unknown Issue';
                        const desc = def.description || def.remediation || '';

                        return (
                          <tr key={index} className="hover:bg-gray-50 transition-colors">
                            <td className="px-4 py-3 font-semibold text-gray-800">{name}</td>
                            <td className="px-4 py-3">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                                severity === 'high' ? 'bg-red-100 text-red-800' :
                                severity === 'medium' ? 'bg-orange-100 text-orange-800' :
                                severity === 'low' ? 'bg-yellow-100 text-yellow-800' : 'bg-blue-100 text-blue-800'
                              }`}>
                                {severity}
                              </span>
                            </td>
                            <td className="px-4 py-3 text-gray-600 leading-relaxed" dangerouslySetInnerHTML={{ __html: desc }} />
                          </tr>
                        );
                      })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default BurpIntegration;
