import React, { useState, useEffect } from 'react';
import axios from 'axios';

function TargetsList() {
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchTargets();
  }, []);

  const fetchTargets = async () => {
    try {
      const response = await axios.get('/api/v1/targets');
      setTargets(response.data);
    } catch (error) {
      console.error('Error fetching targets:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div>Loading...</div>;

  return (
    <div>
      <h2>Targets</h2>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Base URL</th>
            <th>Platform</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {targets.map(target => (
            <tr key={target.id}>
              <td>{target.id}</td>
              <td>{target.name}</td>
              <td>{target.base_url}</td>
              <td>{target.bounty_platform || '-'}</td>
              <td>{target.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default TargetsList;

