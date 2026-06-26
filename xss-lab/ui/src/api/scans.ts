/** One-shot scan API calls */
import api from '@/utils/request';
import type { ScanCreate, ScanResponse } from '@/types/api';

export const scansApi = {
  health: async (): Promise<{ status: string; service: string }> => {
    const response = await api.get<{ status: string; service: string }>('/scans/health');
    return response.data;
  },

  create: async (data: ScanCreate): Promise<ScanResponse> => {
    const response = await api.post<ScanResponse>('/scans/', data);
    return response.data;
  },
};
