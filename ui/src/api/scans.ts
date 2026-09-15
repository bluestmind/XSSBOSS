/** One-shot scan API calls */
import api from '@/utils/request';
import type { ScanCreate, ScanIntervention, ScanResponse } from '@/types/api';

export const scansApi = {
  health: async (): Promise<{ status: string; service: string }> => {
    const response = await api.get<{ status: string; service: string }>('/scans/health');
    return response.data;
  },

  create: async (data: ScanCreate): Promise<ScanResponse> => {
    const response = await api.post<ScanResponse>('/scans/', data);
    return response.data;
  },

  interventions: async (experimentId: number): Promise<ScanIntervention[]> => {
    const response = await api.get<{ items: ScanIntervention[] }>(`/scans/${experimentId}/interventions`);
    return response.data.items;
  },

  resolveIntervention: async (
    experimentId: number,
    interventionId: string,
    data: { resolution: string; auth_info?: Record<string, any> },
  ): Promise<{ remaining_open: number; resumed: boolean }> => {
    const response = await api.post(
      `/scans/${experimentId}/interventions/${interventionId}/resolve`,
      data,
    );
    return response.data;
  },
};
