/** Filter profile API calls */
import api from '@/utils/request';
import type { FilterProfile } from '@/types/api';

export const filtersApi = {
  /** Get filter profile for an endpoint */
  getByEndpoint: async (endpointId: number): Promise<FilterProfile | null> => {
    try {
      const response = await api.get<FilterProfile>(`/filters/endpoint/${endpointId}`);
      return response.data;
    } catch (error: any) {
      if (error.response?.status === 404) {
        return null;
      }
      throw error;
    }
  },

  /** Get filter profile by ID */
  get: async (id: number): Promise<FilterProfile> => {
    const response = await api.get<FilterProfile>(`/filters/${id}`);
    return response.data;
  },
};

