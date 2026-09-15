/** Filter profile display card */
import type { FilterProfile } from '@/types/api';

interface FilterProfileCardProps {
  profile: FilterProfile;
}

const FilterProfileCard = ({ profile }: FilterProfileCardProps) => {
  return (
    <div className="bg-carbon-800/70 rounded-lg shadow p-6 border-l-4 border-yellow-500">
      <div className="flex items-start justify-between mb-4">
        <div>
          <h3 className="text-lg font-semibold text-carbon-100">Filter Profile</h3>
          <p className="text-sm text-carbon-400 mt-1">Endpoint ID: {profile.endpoint_id}</p>
        </div>
        <div className="flex flex-col items-end space-y-1">
          {profile.waf_detected && (
            <span className="px-3 py-1 text-xs font-semibold rounded-full bg-red-500/15 text-red-200">
              WAF Detected
            </span>
          )}
          {profile.sanitizer_detected && (
            <span className="px-3 py-1 text-xs font-semibold rounded-full bg-orange-500/15 text-orange-200">
              {profile.sanitizer_detected}
            </span>
          )}
        </div>
      </div>

      {profile.summary && (
        <div className="mb-4">
          <p className="text-sm text-carbon-200">{profile.summary}</p>
        </div>
      )}

      <div className="space-y-4">
        {profile.blocked_tokens && profile.blocked_tokens.length > 0 && (
          <div>
            <h4 className="text-sm font-semibold text-carbon-200 mb-2">Blocked Tokens:</h4>
            <div className="flex flex-wrap gap-2">
              {profile.blocked_tokens.map((token: string, idx: number) => (
                <span
                  key={idx}
                  className="px-2 py-1 text-xs font-semibold rounded bg-red-500/15 text-red-200"
                >
                  {token}
                </span>
              ))}
            </div>
          </div>
        )}

        {profile.allowed_tokens && profile.allowed_tokens.length > 0 && (
          <div>
            <h4 className="text-sm font-semibold text-carbon-200 mb-2">Allowed Tokens:</h4>
            <div className="flex flex-wrap gap-2">
              {profile.allowed_tokens.map((token: string, idx: number) => (
                <span
                  key={idx}
                  className="px-2 py-1 text-xs font-semibold rounded bg-green-500/15 text-green-200"
                >
                  {token}
                </span>
              ))}
            </div>
          </div>
        )}

        {profile.normalization_behavior && profile.normalization_behavior.length > 0 && (
          <div>
            <h4 className="text-sm font-semibold text-carbon-200 mb-2">Normalization:</h4>
            <div className="flex flex-wrap gap-2">
              {profile.normalization_behavior.map((behavior: string, idx: number) => (
                <span
                  key={idx}
                  className="px-2 py-1 text-xs font-semibold rounded bg-yellow-500/15 text-yellow-200"
                >
                  {behavior}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="mt-4 pt-4 border-t border-carbon-700/60">
        <p className="text-xs text-carbon-400">
          Profiled: {new Date(profile.profiled_at).toLocaleString()}
        </p>
      </div>
    </div>
  );
};

export default FilterProfileCard;

