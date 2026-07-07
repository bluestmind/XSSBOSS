/** Parameter API calls */
import api from '@/utils/request';
import type { Param } from '@/types/api';

export const paramsApi = {
  /** Get parameters for an endpoint */
  getByEndpoint: async (endpointId: number): Promise<Param[]> => {
    const response = await api.get<Param[]>('/params/', {
      params: { endpoint_id: endpointId },
    });
    return response.data;
  },

  /** Get parameter by ID */
  get: async (id: number): Promise<Param> => {
    const response = await api.get<Param>(`/params/${id}`);
    return response.data;
  },
};

