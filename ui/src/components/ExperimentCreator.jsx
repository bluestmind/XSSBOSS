import React, { useState, useEffect } from 'react';
import axios from 'axios';

function ExperimentCreator() {
  const [targets, setTargets] = useState([]);
  const [experiments, setExperiments] = useState([]);
  const [formData, setFormData] = useState({
    target_id: '',
    name: '',
    strategy: 'quick_light'
  });

  useEffect(() => {
    fetchTargets();
    fetchExperiments();
  }, []);

  const fetchTargets = async () => {
    try {
      const response = await axios.get('/api/v1/targets');
      setTargets(response.data);
    } catch (error) {
      console.error('Error fetching targets:', error);
    }
  };

  const fetchExperiments = async () => {
    try {
      const response = await axios.get('/api/v1/experiments');
      setExperiments(response.data);
    } catch (error) {
      console.error('Error fetching experiments:', error);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await axios.post('/api/v1/experiments', formData);
      alert('Experiment created!');
      fetchExperiments();
      setFormData({ target_id: '', name: '', strategy: 'quick_light' });
    } catch (error) {
      console.error('Error creating experiment:', error);
      alert('Error creating experiment');
    }
  };

  const handleStart = async (id) => {
    try {
      await axios.post(`/api/v1/experiments/${id}/start`);
      alert('Experiment started!');
      fetchExperiments();
    } catch (error) {
      console.error('Error starting experiment:', error);
      alert('Error starting experiment');
    }
  };

  return (
    <div>
      <h2>Experiments</h2>
      
      <form onSubmit={handleSubmit}>
        <div>
          <label>Target:</label>
          <select
            value={formData.target_id}
            onChange={(e) => setFormData({ ...formData, target_id: e.target.value })}
            required
          >
            <option value="">Select target</option>
            {targets.map(t => (
              <option key={t.id} value={t.id}>{t.name}</option>
            ))}
          </select>
        </div>
        
        <div>
          <label>Name:</label>
          <input
            type="text"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            required
          />
        </div>
        
        <div>
          <label>Strategy:</label>
          <select
            value={formData.strategy}
            onChange={(e) => setFormData({ ...formData, strategy: e.target.value })}
          >
            <option value="quick_light">Quick & Light</option>
            <option value="unicode_hunt">Unicode Hunt</option>
            <option value="js_string_specialist">JS String Specialist</option>
            <option value="csp_aware">CSP Aware</option>
          </select>
        </div>
        
        <button type="submit">Create Experiment</button>
      </form>
      
      <h3>Existing Experiments</h3>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Strategy</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {experiments.map(exp => (
            <tr key={exp.id}>
              <td>{exp.id}</td>
              <td>{exp.name}</td>
              <td>{exp.strategy}</td>
              <td>{exp.status}</td>
              <td>
                {exp.status === 'pending' && (
                  <button onClick={() => handleStart(exp.id)}>Start</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default ExperimentCreator;

