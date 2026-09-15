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

  /** Get self-improving parameter vocabulary */
  getDictionary: async (category?: string, query?: string) => {
    const params = new URLSearchParams();
    if (category) params.append('category', category);
    if (query) params.append('query', query);
    const response = await api.get(`/params/dictionary?${params.toString()}`);
    return response.data;
  },

  /** Add/train custom parameter into the dictionary */
  addCustomParam: async (paramName: string, category: string = 'redirect', source: string = 'Operator UI') => {
    const response = await api.post('/params/dictionary', {
      param_name: paramName,
      category,
      source,
    });
    return response.data;
  },
};


