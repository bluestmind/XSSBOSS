/** Experiment API calls */
import api from '@/utils/request';
import type { Experiment, ExperimentCreate, ExperimentMonitor, ExperimentStats } from '@/types/api';

export const experimentsApi = {
  /** Get all experiments, optionally filtered by target_id or status */
  list: async (targetId?: number, status?: string): Promise<Experiment[]> => {
    const params: Record<string, any> = {};
    if (targetId) params.target_id = targetId;
    if (status) params.status = status;
    const response = await api.get<Experiment[]>('/experiments/', { params });
    return response.data;
  },

  /** Get experiment by ID */
  get: async (id: number): Promise<Experiment> => {
    const response = await api.get<Experiment>(`/experiments/${id}`);
    return response.data;
  },

  /** Create new experiment */
  create: async (data: ExperimentCreate): Promise<Experiment> => {
    const response = await api.post<Experiment>('/experiments/', data);
    return response.data;
  },

  /** Update experiment */
  update: async (id: number, data: Partial<ExperimentCreate>): Promise<Experiment> => {
    const response = await api.put<Experiment>(`/experiments/${id}`, data);
    return response.data;
  },

  /** Start experiment */
  start: async (id: number): Promise<Experiment> => {
    const response = await api.post<Experiment>(`/experiments/${id}/start`);
    return response.data;
  },

  /** Stop/pause experiment */
  stop: async (id: number): Promise<Experiment> => {
    const response = await api.post<Experiment>(`/experiments/${id}/stop`);
    return response.data;
  },

  /** Continue/resume experiment */
  resume: async (id: number): Promise<Experiment> => {
    const response = await api.post<Experiment>(`/experiments/${id}/continue`);
    return response.data;
  },

  /** Get experiment statistics */
  getStats: async (id: number): Promise<ExperimentStats> => {
    const response = await api.get<ExperimentStats>(`/experiments/${id}/stats`);
    return response.data;
  },

  /** Get live monitor snapshot */
  getMonitor: async (id: number): Promise<ExperimentMonitor> => {
    const response = await api.get<ExperimentMonitor>(`/experiments/${id}/monitor`);
    return response.data;
  },

  /** Delete experiment */
  delete: async (id: number): Promise<void> => {
    await api.delete(`/experiments/${id}`);
  },
};

