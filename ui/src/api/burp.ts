/** Burp Suite API calls */
import api from '@/utils/request';

export const burpApi = {
  /** Automatically launch and sync a Burp scan for a target */
  autoSync: async (targetId: number): Promise<any> => {
    const response = await api.post(`/burp/auto-sync/${targetId}`);
    return response.data;
  },

  /** Upload XML file */
  uploadXml: async (targetId: number, file: File): Promise<any> => {
    const formData = new FormData();
    formData.append('target_id', targetId.toString());
    formData.append('file', file);
    
    const response = await api.post('/burp/xml', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  /** Import from Burp REST API */
  importRest: async (targetId: number, apiUrl: string, apiKey?: string, taskId?: string): Promise<any> => {
    const response = await api.post('/burp/rest-import', {
      target_id: targetId,
      api_url: apiUrl,
      api_key: apiKey || null,
      task_id: taskId || null,
    });
    return response.data;
  },

  /** Trigger Burp scan */
  triggerScan: async (apiUrl: string, targetUrls: string[], apiKey?: string): Promise<any> => {
    const response = await api.post('/burp/trigger-scan', {
      api_url: apiUrl,
      target_urls: targetUrls,
      api_key: apiKey || null,
    });
    return response.data;
  },

  /** Send a finding request to Burp Suite tool queue (Repeater or Intruder) */
  sendToRepeater: async (findingId: number, tool: string = 'repeater'): Promise<any> => {
    const response = await api.post('/burp/send-to-repeater', {
      finding_id: findingId,
      tool: tool,
    });
    return response.data;
  },

  /** Get scan tasks from Burp REST API */
  getScanTasks: async (apiUrl: string, apiKey?: string): Promise<any> => {
    const response = await api.get('/burp/scan-tasks', {
      params: {
        api_url: apiUrl,
        api_key: apiKey || null,
      },
    });
    return response.data;
  },

  /** Get details of a scan task */
  getScanTask: async (apiUrl: string, taskId: string, apiKey?: string): Promise<any> => {
    const response = await api.get(`/burp/scan-tasks/${taskId}`, {
      params: {
        api_url: apiUrl,
        api_key: apiKey || null,
      },
    });
    return response.data;
  },

  /** Cancel/delete a scan task */
  cancelScanTask: async (apiUrl: string, taskId: string, apiKey?: string): Promise<any> => {
    const response = await api.delete(`/burp/scan-tasks/${taskId}`, {
      params: {
        api_url: apiUrl,
        api_key: apiKey || null,
      },
    });
    return response.data;
  },

  /** Get issue definitions library from Burp Knowledge Base */
  getIssueDefinitions: async (apiUrl: string, apiKey?: string): Promise<any> => {
    const response = await api.get('/burp/issue-definitions', {
      params: {
        api_url: apiUrl,
        api_key: apiKey || null,
      },
    });
    return response.data;
  },
};
