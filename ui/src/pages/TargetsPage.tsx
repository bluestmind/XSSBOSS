/** Targets page */
import { useQuery } from '@tanstack/react-query';
import { useUIStore } from '@/store/uiState';
import { targetsApi } from '@/api/targets';
import TargetTable from '@/components/tables/TargetTable';
import CreateTargetModal from '@/components/modals/CreateTargetModal';
import ImportProgramsModal from '@/components/modals/ImportProgramsModal';
import StatCard from '@/components/cards/StatCard';

const TargetsPage = () => {
  const { openModal } = useUIStore();

  const { data: targets = [] } = useQuery({
    queryKey: ['targets'],
    queryFn: targetsApi.list,
  });

  const stats = {
    total: targets.length,
    fuzzing: targets.filter((t: any) => t.status === 'fuzzing').length,
    triage: targets.filter((t: any) => t.status === 'triage').length,
    done: targets.filter((t: any) => t.status === 'done').length,
  };

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Targets</h1>
        <div className="flex items-center gap-3">
          <button
            onClick={() => openModal('import-programs')}
            className="px-4 py-2 bg-white text-blue-700 border border-blue-200 rounded-md hover:bg-blue-50"
          >
            Import Programs
          </button>
          <button
            onClick={() => openModal('create-target')}
            className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
          >
            + Create Target
          </button>
        </div>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <StatCard label="Total Targets" value={stats.total} icon="🎯" color="blue" />
        <StatCard label="Fuzzing" value={stats.fuzzing} icon="🧪" color="blue" />
        <StatCard label="Triage" value={stats.triage} icon="📋" color="yellow" />
        <StatCard label="Completed" value={stats.done} icon="✅" color="green" />
      </div>

      {/* Targets table */}
      <TargetTable />

      <CreateTargetModal />
      <ImportProgramsModal />
    </div>
  );
};

export default TargetsPage;

