/** Endpoint API calls */
import api from '@/utils/request';
import type { Endpoint } from '@/types/api';

export const endpointsApi = {
  /** Get all endpoints, optionally filtered by target_id */
  list: async (targetId?: number): Promise<Endpoint[]> => {
    const params = targetId ? { target_id: targetId } : {};
    const response = await api.get<Endpoint[]>('/endpoints/', { params });
    return response.data;
  },

  /** Get endpoint by ID */
  get: async (id: number): Promise<Endpoint> => {
    const response = await api.get<Endpoint>(`/endpoints/${id}`);
    return response.data;
  },

  /** Create new endpoint */
  create: async (data: Partial<Endpoint>): Promise<Endpoint> => {
    const response = await api.post<Endpoint>('/endpoints/', data);
    return response.data;
  },

  /** Delete endpoint */
  delete: async (id: number): Promise<void> => {
    await api.delete(`/endpoints/${id}`);
  },
};

