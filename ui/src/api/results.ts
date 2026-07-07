/** Results and findings API calls */
import api from '@/utils/request';
import type { Finding, Execution } from '@/types/api';

export const resultsApi = {
  /** Get all findings, optionally filtered */
  listFindings: async (
    targetId?: number,
    endpointId?: number,
    status?: string,
    severity?: string
  ): Promise<Finding[]> => {
    const params: Record<string, any> = {};
    if (targetId) params.target_id = targetId;
    if (endpointId) params.endpoint_id = endpointId;
    if (status) params.status = status;
    if (severity) params.severity = severity;
    const response = await api.get<Finding[]>('/results/findings', { params });
    return response.data;
  },

  /** Get finding by ID */
  getFinding: async (id: number): Promise<Finding> => {
    const response = await api.get<Finding>(`/results/findings/${id}`);
    return response.data;
  },

  /** Get all executions, optionally filtered */
  listExecutions: async (
    testCaseId?: number,
    oracleStatus?: string
  ): Promise<Execution[]> => {
    const params: Record<string, any> = {};
    if (testCaseId) params.test_case_id = testCaseId;
    if (oracleStatus) params.oracle_status = oracleStatus;
    const response = await api.get<Execution[]>('/results/executions', { params });
    return response.data;
  },

  /** Get execution by ID */
  getExecution: async (id: number): Promise<Execution> => {
    const response = await api.get<Execution>(`/results/executions/${id}`);
    return response.data;
  },

  /** Replay finding proof of concept */
  replayFinding: async (id: number): Promise<{ status: string; message: string }> => {
    const response = await api.post<{ status: string; message: string }>(`/results/findings/${id}/replay`);
    return response.data;
  },
};

