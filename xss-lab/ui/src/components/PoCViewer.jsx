import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import axios from 'axios';

function PoCViewer() {
  const { id } = useParams();
  const [finding, setFinding] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchFinding();
  }, [id]);

  const fetchFinding = async () => {
    try {
      const response = await axios.get(`/api/v1/results/findings/${id}`);
      setFinding(response.data);
    } catch (error) {
      console.error('Error fetching finding:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div>Loading...</div>;
  if (!finding) return <div>Finding not found</div>;

  return (
    <div>
      <h2>XSS Finding #{finding.id}</h2>
      
      <div>
        <h3>Payload</h3>
        <pre><code>{finding.best_payload}</code></pre>
      </div>
      
      <div>
        <h3>Severity</h3>
        <p>{finding.severity}</p>
      </div>
      
      <div>
        <h3>Status</h3>
        <p>{finding.status}</p>
      </div>
      
      {finding.report_text && (
        <div>
          <h3>Report</h3>
          <p>{finding.report_text}</p>
        </div>
      )}
      
      {finding.poc_request && (
        <div>
          <h3>PoC Request</h3>
          <pre><code>{JSON.stringify(finding.poc_request, null, 2)}</code></pre>
        </div>
      )}
      
      {finding.screenshot_path && (
        <div>
          <h3>Screenshot</h3>
          <img src={`/api/v1/files/${finding.screenshot_path}`} alt="XSS PoC" />
        </div>
      )}
    </div>
  );
}

export default PoCViewer;

