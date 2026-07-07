/** Bug bounty program import API calls */
import api from '@/utils/request';
import type { ProgramImportRequest, ProgramImportResponse } from '@/types/api';

export const programImportApi = {
  importBugBountyPrograms: async (
    data: ProgramImportRequest
  ): Promise<ProgramImportResponse> => {
    const response = await api.post<ProgramImportResponse>('/program-imports/bug-bounty', data);
    return response.data;
  },
};
