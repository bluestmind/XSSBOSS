/** Import bug bounty programs modal */
import { useState, type FormEvent } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { programImportApi } from '@/api/programImport';
import { useUIStore } from '@/store/uiState';
import type { ProgramImportRequest, ProgramImportResponse } from '@/types/api';

const DEFAULT_PROFILE_PATH = '~/.xssboss/browser_profile';
const YESWEHACK_TYPES = ['bug-bounty', 'vdp', 'pentest', 'vdp-in-app'];

const parseList = (value: string) =>
  value
    .split(/[\s,]+/)
    .map((item) => item.trim())
    .filter(Boolean);

const toggleValue = (values: string[], value: string) =>
  values.includes(value) ? values.filter((item) => item !== value) : [...values, value];

const ImportProgramsModal = () => {
  const { activeModal, closeModal } = useUIStore();
  const queryClient = useQueryClient();
  const isOpen = activeModal === 'import-programs';

  const [platforms, setPlatforms] = useState<string[]>(['hackerone', 'yeswehack']);
  const [yeswehackTypes, setYeswehackTypes] = useState<string[]>(YESWEHACK_TYPES);
  const [handles, setHandles] = useState('');
  const [slugs, setSlugs] = useState('');
  const [limit, setLimit] = useState(25);
  const [maxScopes, setMaxScopes] = useState(500);
  const [updateExisting, setUpdateExisting] = useState(true);
  const [dryRun, setDryRun] = useState(false);
  const [profilePath, setProfilePath] = useState(DEFAULT_PROFILE_PATH);
  const [profileName, setProfileName] = useState('Default');
  const [result, setResult] = useState<ProgramImportResponse | null>(null);

  const mutation = useMutation({
    mutationFn: (payload: ProgramImportRequest) =>
      programImportApi.importBugBountyPrograms(payload),
    onSuccess: (data) => {
      setResult(data);
      if (!data.dry_run) {
        queryClient.invalidateQueries({ queryKey: ['targets'] });
      }
    },
  });

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    setResult(null);
    mutation.mutate({
      platforms,
      handles: parseList(handles),
      slugs: parseList(slugs),
      limit_per_platform: limit,
      max_scopes_per_program: maxScopes,
      yeswehack_types: yeswehackTypes,
      update_existing: updateExisting,
      dry_run: dryRun,
      browser_profile_path: profilePath,
      browser_profile_name: profileName,
    });
  };

  const errorMessage = mutation.error
    ? ((mutation.error as any).response?.data?.detail || (mutation.error as Error).message)
    : null;

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex min-h-screen items-center justify-center px-4 pt-4 pb-20 text-center sm:block sm:p-0">
        <div className="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" onClick={closeModal} />

        <div className="inline-block max-h-[90vh] overflow-y-auto align-bottom bg-white rounded-lg text-left shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-3xl sm:w-full">
          <form onSubmit={handleSubmit}>
            <div className="bg-white px-4 pt-5 pb-4 sm:p-6">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Import Programs</h3>

              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Platforms</label>
                  <div className="flex gap-3">
                    {['hackerone', 'yeswehack'].map((platform) => (
                      <label key={platform} className="inline-flex items-center gap-2 text-sm text-gray-700">
                        <input
                          type="checkbox"
                          checked={platforms.includes(platform)}
                          onChange={() => setPlatforms(toggleValue(platforms, platform))}
                          className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                        />
                        {platform}
                      </label>
                    ))}
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">YesWeHack Types</label>
                  <div className="flex flex-wrap gap-3">
                    {YESWEHACK_TYPES.map((programType) => (
                      <label key={programType} className="inline-flex items-center gap-2 text-sm text-gray-700">
                        <input
                          type="checkbox"
                          checked={yeswehackTypes.includes(programType)}
                          onChange={() => setYeswehackTypes(toggleValue(yeswehackTypes, programType))}
                          className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                        />
                        {programType}
                      </label>
                    ))}
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700">HackerOne Handles</label>
                  <textarea
                    rows={3}
                    value={handles}
                    onChange={(event) => setHandles(event.target.value)}
                    placeholder="example example-private"
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700">YesWeHack Slugs</label>
                  <textarea
                    rows={3}
                    value={slugs}
                    onChange={(event) => setSlugs(event.target.value)}
                    placeholder="example-program another-program"
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700">Limit Per Platform</label>
                  <input
                    type="number"
                    min={1}
                    max={100}
                    value={limit}
                    onChange={(event) => setLimit(Number(event.target.value))}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700">Max Scopes Per Program</label>
                  <input
                    type="number"
                    min={1}
                    max={10000}
                    value={maxScopes}
                    onChange={(event) => setMaxScopes(Number(event.target.value))}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700">Browser Profile Path</label>
                  <input
                    type="text"
                    value={profilePath}
                    onChange={(event) => setProfilePath(event.target.value)}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700">Profile Directory</label>
                  <input
                    type="text"
                    value={profileName}
                    onChange={(event) => setProfileName(event.target.value)}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  />
                </div>
              </div>

              <div className="mt-4 flex flex-wrap gap-4">
                <label className="inline-flex items-center gap-2 text-sm text-gray-700">
                  <input
                    type="checkbox"
                    checked={updateExisting}
                    onChange={(event) => setUpdateExisting(event.target.checked)}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                  Update existing
                </label>
                <label className="inline-flex items-center gap-2 text-sm text-gray-700">
                  <input
                    type="checkbox"
                    checked={dryRun}
                    onChange={(event) => setDryRun(event.target.checked)}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                  Dry run
                </label>
              </div>

              {errorMessage && (
                <div className="mt-4 rounded-md bg-red-50 p-3 text-sm text-red-700">
                  {errorMessage}
                </div>
              )}

              {result && (
                <div className="mt-5">
                  <div className="mb-3 grid grid-cols-2 gap-3 text-sm md:grid-cols-4">
                    <div className="rounded-md bg-gray-50 p-3">
                      <div className="text-gray-500">Imported</div>
                      <div className="text-lg font-semibold text-gray-900">{result.imported}</div>
                    </div>
                    <div className="rounded-md bg-gray-50 p-3">
                      <div className="text-gray-500">Updated</div>
                      <div className="text-lg font-semibold text-gray-900">{result.updated}</div>
                    </div>
                    <div className="rounded-md bg-gray-50 p-3">
                      <div className="text-gray-500">Skipped</div>
                      <div className="text-lg font-semibold text-gray-900">{result.skipped}</div>
                    </div>
                    <div className="rounded-md bg-gray-50 p-3">
                      <div className="text-gray-500">Errors</div>
                      <div className="text-lg font-semibold text-gray-900">{result.errors.length}</div>
                    </div>
                  </div>

                  {result.targets.length > 0 && (
                    <div className="overflow-x-auto rounded-md border border-gray-200">
                      <table className="min-w-full divide-y divide-gray-200">
                        <thead className="bg-gray-50">
                          <tr>
                            <th className="px-3 py-2 text-left text-xs font-medium uppercase text-gray-500">Action</th>
                            <th className="px-3 py-2 text-left text-xs font-medium uppercase text-gray-500">Program</th>
                            <th className="px-3 py-2 text-left text-xs font-medium uppercase text-gray-500">Platform</th>
                            <th className="px-3 py-2 text-left text-xs font-medium uppercase text-gray-500">Scope</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-200 bg-white">
                          {result.targets.slice(0, 10).map((target) => (
                            <tr key={`${target.platform}-${target.program_key}`}>
                              <td className="px-3 py-2 text-sm text-gray-600">{target.action}</td>
                              <td className="px-3 py-2 text-sm font-medium text-gray-900">{target.name}</td>
                              <td className="px-3 py-2 text-sm text-gray-600">{target.platform}</td>
                              <td className="px-3 py-2 text-sm text-gray-600">
                                {target.in_scope_count} / {target.out_of_scope_count}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                  {result.errors.length > 0 && (
                    <div className="mt-3 rounded-md bg-yellow-50 p-3 text-sm text-yellow-800">
                      {result.errors.map((error) => (
                        <div key={`${error.platform}-${error.program_key || error.message}`}>
                          {error.platform}: {error.message}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="bg-gray-50 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
              <button
                type="submit"
                disabled={mutation.isPending || platforms.length === 0}
                className="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-blue-600 text-base font-medium text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:ml-3 sm:w-auto sm:text-sm disabled:opacity-50"
              >
                {mutation.isPending ? 'Importing...' : 'Import Programs'}
              </button>
              <button
                type="button"
                onClick={closeModal}
                className="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
              >
                Close
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default ImportProgramsModal;
