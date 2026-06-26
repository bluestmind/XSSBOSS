/** Formatting utilities */
import { format, formatDistanceToNow } from 'date-fns';
import { STATUS_COLORS, METHOD_COLORS, LOCATION_COLORS, CONTEXT_TYPE_LABELS, SINK_TYPE_LABELS, STRATEGY_LABELS } from './constants';

export const formatDate = (dateString: string): string => {
  try {
    return format(new Date(dateString), 'yyyy-MM-dd HH:mm:ss');
  } catch {
    return dateString;
  }
};

export const formatRelativeTime = (dateString: string): string => {
  try {
    return formatDistanceToNow(new Date(dateString), { addSuffix: true });
  } catch {
    return dateString;
  }
};

export const getStatusColor = (status: string): string => {
  return STATUS_COLORS[status] || 'bg-gray-100 text-gray-800';
};

export const getMethodColor = (method: string): string => {
  return METHOD_COLORS[method.toUpperCase()] || 'bg-gray-100 text-gray-800';
};

export const getLocationColor = (location: string): string => {
  return LOCATION_COLORS[location] || 'bg-gray-100 text-gray-800';
};

export const getContextTypeLabel = (type: string): string => {
  return CONTEXT_TYPE_LABELS[type] || type;
};

export const getSinkTypeLabel = (type: string): string => {
  return SINK_TYPE_LABELS[type] || type;
};

export const getStrategyLabel = (strategy: string): string => {
  return STRATEGY_LABELS[strategy] || strategy;
};

export const truncate = (text: string, maxLength: number): string => {
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength) + '...';
};

export const formatPayload = (payload: string, maxLength: number = 100): string => {
  return truncate(payload, maxLength);
};

