/** Target API calls */
import api from '@/utils/request';
import type { Target, TargetCreate } from '@/types/api';

export const targetsApi = {
  /** Get all targets */
  list: async (): Promise<Target[]> => {
    const response = await api.get<Target[]>('/targets/');
    return response.data;
  },

  /** Get target by ID */
  get: async (id: number): Promise<Target> => {
    const response = await api.get<Target>(`/targets/${id}`);
    return response.data;
  },

  /** Create new target */
  create: async (data: TargetCreate): Promise<Target> => {
    const response = await api.post<Target>('/targets/', data);
    return response.data;
  },

  /** Update target */
  update: async (id: number, data: Partial<TargetCreate>): Promise<Target> => {
    const response = await api.put<Target>(`/targets/${id}`, data);
    return response.data;
  },

  /** Delete target */
  delete: async (id: number): Promise<void> => {
    await api.delete(`/targets/${id}`);
  },
};

