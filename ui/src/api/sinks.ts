/** Sink API calls */
import api from '@/utils/request';
import type { Sink } from '@/types/api';

export const sinksApi = {
  /** Get sinks for a context */
  getByContext: async (contextId: number): Promise<Sink[]> => {
    const response = await api.get<Sink[]>('/sinks/', {
      params: { context_id: contextId },
    });
    return response.data;
  },

  /** Get sink by ID */
  get: async (id: number): Promise<Sink> => {
    const response = await api.get<Sink>(`/sinks/${id}`);
    return response.data;
  },
};

