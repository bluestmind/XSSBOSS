/** Create target modal */
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { targetsApi } from '@/api/targets';
import { useUIStore } from '@/store/uiState';
import type { TargetCreate } from '@/types/api';

const CreateTargetModal = () => {
  const { activeModal, closeModal } = useUIStore();
  const queryClient = useQueryClient();
  const isOpen = activeModal === 'create-target';

  const [formData, setFormData] = useState<TargetCreate>({
    name: '',
    base_url: '',
    notes: '',
    bounty_platform: '',
    scope_tags: {},
    auth_info: {},
  });

  const mutation = useMutation({
    mutationFn: targetsApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['targets'] });
      closeModal();
      setFormData({
        name: '',
        base_url: '',
        notes: '',
        bounty_platform: '',
        scope_tags: {},
        auth_info: {},
      });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    mutation.mutate(formData);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:block sm:p-0">
        <div className="fixed inset-0 transition-opacity bg-carbon-950/80 backdrop-blur-sm" onClick={closeModal} />

        <div className="inline-block align-bottom bg-carbon-850 rounded-xl border border-carbon-700 text-left overflow-hidden shadow-2xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
          <form onSubmit={handleSubmit}>
            <div className="bg-carbon-850 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
              <h3 className="text-lg font-medium text-carbon-100 mb-4">Create New Target</h3>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-carbon-200">Name *</label>
                  <input
                    type="text"
                    required
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    className="mt-1 block w-full rounded-md border-carbon-600 shadow-sm focus:border-brand-500 focus:ring-brand-500 sm:text-sm"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-carbon-200">Base URL *</label>
                  <input
                    type="url"
                    required
                    value={formData.base_url}
                    onChange={(e) => setFormData({ ...formData, base_url: e.target.value })}
                    className="mt-1 block w-full rounded-md border-carbon-600 shadow-sm focus:border-brand-500 focus:ring-brand-500 sm:text-sm"
                    placeholder="https://example.com"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-carbon-200">Bounty Platform</label>
                  <input
                    type="text"
                    value={formData.bounty_platform || ''}
                    onChange={(e) => setFormData({ ...formData, bounty_platform: e.target.value })}
                    className="mt-1 block w-full rounded-md border-carbon-600 shadow-sm focus:border-brand-500 focus:ring-brand-500 sm:text-sm"
                    placeholder="intigriti, hackerone, etc."
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-carbon-200">Notes</label>
                  <textarea
                    value={formData.notes || ''}
                    onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
                    rows={3}
                    className="mt-1 block w-full rounded-md border-carbon-600 shadow-sm focus:border-brand-500 focus:ring-brand-500 sm:text-sm"
                  />
                </div>
              </div>
            </div>

            <div className="bg-carbon-850/50 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
              <button
                type="submit"
                disabled={mutation.isPending}
                className="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-brand-600 text-base font-medium text-white hover:bg-brand-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-brand-500 sm:ml-3 sm:w-auto sm:text-sm disabled:opacity-50"
              >
                {mutation.isPending ? 'Creating...' : 'Create Target'}
              </button>
              <button
                type="button"
                onClick={closeModal}
                className="mt-3 w-full inline-flex justify-center rounded-md border border-carbon-600 shadow-sm px-4 py-2 bg-carbon-850 text-base font-medium text-carbon-200 hover:bg-carbon-850/50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-brand-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default CreateTargetModal;

