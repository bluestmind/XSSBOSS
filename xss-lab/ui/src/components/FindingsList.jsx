import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';

function FindingsList() {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchFindings();
  }, []);

  const fetchFindings = async () => {
    try {
      const response = await axios.get('/api/v1/results/findings');
      setFindings(response.data);
    } catch (error) {
      console.error('Error fetching findings:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div>Loading...</div>;

  return (
    <div>
      <h2>XSS Findings</h2>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Payload</th>
            <th>Severity</th>
            <th>Status</th>
            <th>Created</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {findings.map(finding => (
            <tr key={finding.id}>
              <td>{finding.id}</td>
              <td><code>{finding.best_payload.substring(0, 50)}...</code></td>
              <td>{finding.severity}</td>
              <td>{finding.status}</td>
              <td>{new Date(finding.created_at).toLocaleDateString()}</td>
              <td>
                <Link to={`/findings/${finding.id}`}>View PoC</Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default FindingsList;

