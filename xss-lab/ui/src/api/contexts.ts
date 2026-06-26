/** Context API calls */
import api from '@/utils/request';
import type { Context } from '@/types/api';

export const contextsApi = {
  /** Get contexts for a parameter */
  getByParam: async (paramId: number): Promise<Context[]> => {
    const response = await api.get<Context[]>('/contexts/', {
      params: { param_id: paramId },
    });
    return response.data;
  },

  /** Get contexts for an endpoint */
  getByEndpoint: async (endpointId: number): Promise<Context[]> => {
    const response = await api.get<Context[]>('/contexts/', {
      params: { endpoint_id: endpointId },
    });
    return response.data;
  },

  /** Get context by ID */
  get: async (id: number): Promise<Context> => {
    const response = await api.get<Context>(`/contexts/${id}`);
    return response.data;
  },
};

