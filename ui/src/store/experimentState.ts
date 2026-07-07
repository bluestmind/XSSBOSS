/** Experiment state management */
import { create } from 'zustand';

interface ExperimentState {
  activeExperimentId: number | null;
  pollingInterval: number;
  setActiveExperiment: (id: number) => void;
  clearActiveExperiment: () => void;
  setPollingInterval: (interval: number) => void;
}

export const useExperimentStore = create<ExperimentState>((set) => ({
  activeExperimentId: null,
  pollingInterval: 5000, // 5 seconds
  setActiveExperiment: (id) => set({ activeExperimentId: id }),
  clearActiveExperiment: () => set({ activeExperimentId: null }),
  setPollingInterval: (interval) => set({ pollingInterval: interval }),
}));

