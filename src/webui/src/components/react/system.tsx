import { api } from '@/api';
import { useEffect, Fragment, useState } from 'react';
import Loader from '@/components/react/loader';
import Header from '@/components/react/header';
import ToastContainer from '@/components/react/toast';
import { useToast } from '@/components/react/useToast';

interface SystemInfo {
	hostname: string;
	os_type: string;
	os_version: string;
	cpu_count: number;
	total_memory: number;
	available_memory: number;
	used_memory: number;
	memory_percent: number;
	uptime: number;
	process_count: number;
}

const SystemPage = (props: { base: string }) => {
	const { toasts, closeToast, error } = useToast();
	const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
	const [loading, setLoading] = useState(true);

	const formatBytes = (bytes: number): string => {
		const units = ['B', 'KB', 'MB', 'GB', 'TB'];
		let size = bytes;
		let unitIndex = 0;
		
		while (size >= 1024 && unitIndex < units.length - 1) {
			size /= 1024;
			unitIndex++;
		}
		
		return `${size.toFixed(2)} ${units[unitIndex]}`;
	};

	const formatUptime = (seconds: number): string => {
		const days = Math.floor(seconds / 86400);
		const hours = Math.floor((seconds % 86400) / 3600);
		const minutes = Math.floor((seconds % 3600) / 60);
		
		const parts = [];
		if (days > 0) parts.push(`${days}d`);
		if (hours > 0) parts.push(`${hours}h`);
		if (minutes > 0) parts.push(`${minutes}m`);
		
		return parts.length > 0 ? parts.join(' ') : 'Just started';
	};

	const fetchSystemInfo = async () => {
		setLoading(true);
		try {
			const response = await api.get(`${props.base}/daemon/system`).json<SystemInfo>();
			setSystemInfo(response);
		} catch (err) {
			error('Failed to fetch system info: ' + (err as Error).message);
		} finally {
			setLoading(false);
		}
	};

	useEffect(() => {
		fetchSystemInfo();
		const interval = setInterval(fetchSystemInfo, 5000); // Refresh every 5 seconds
		return () => clearInterval(interval);
	}, []);

	if (loading || !systemInfo) {
		return <Loader />;
	}

	return (
		<Fragment>
			<ToastContainer toasts={toasts} onClose={closeToast} />
			<Header name="System Information" description="Overview of system resources and status.">
				<div className="flex gap-2">
					<button
						type="button"
						onClick={fetchSystemInfo}
						className="transition inline-flex items-center justify-center space-x-1.5 border focus:outline-none focus:ring-0 focus:ring-offset-0 focus:z-10 shrink-0 border-zinc-900 hover:border-zinc-800 bg-zinc-950 text-zinc-50 hover:bg-zinc-900 px-4 py-2 text-sm font-semibold rounded-lg">
						Refresh
					</button>
				</div>
			</Header>

			<div className="space-y-6 px-4 sm:px-6 lg:px-8">
				{/* System Overview */}
				<div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
					<div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6">
						<div className="text-zinc-400 text-sm mb-2">Hostname</div>
						<div className="text-2xl font-bold text-zinc-100">{systemInfo.hostname}</div>
					</div>
					
					<div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6">
						<div className="text-zinc-400 text-sm mb-2">Operating System</div>
						<div className="text-2xl font-bold text-zinc-100">{systemInfo.os_type}</div>
						<div className="text-sm text-zinc-500">{systemInfo.os_version}</div>
					</div>
					
					<div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6">
						<div className="text-zinc-400 text-sm mb-2">CPU Cores</div>
						<div className="text-2xl font-bold text-zinc-100">{systemInfo.cpu_count}</div>
					</div>
					
					<div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6">
						<div className="text-zinc-400 text-sm mb-2">Uptime</div>
						<div className="text-2xl font-bold text-zinc-100">{formatUptime(systemInfo.uptime)}</div>
					</div>
				</div>

				{/* Memory Usage */}
				<div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6">
					<h3 className="text-lg font-semibold text-zinc-200 mb-4">Memory Usage</h3>
					<div className="space-y-4">
						<div>
							<div className="flex justify-between text-sm mb-2">
								<span className="text-zinc-400">Used</span>
								<span className="text-zinc-200 font-medium">
									{formatBytes(systemInfo.used_memory)} / {formatBytes(systemInfo.total_memory)}
									<span className="text-zinc-400 ml-2">
										({systemInfo.memory_percent.toFixed(1)}%)
									</span>
								</span>
							</div>
							<div className="w-full bg-zinc-800 rounded-full h-3 overflow-hidden">
								<div
									className={`h-full transition-all duration-300 ${
										systemInfo.memory_percent > 90
											? 'bg-red-500'
											: systemInfo.memory_percent > 70
											? 'bg-yellow-500'
											: 'bg-emerald-500'
									}`}
									style={{ width: `${systemInfo.memory_percent}%` }}
								/>
							</div>
						</div>
						
						<div className="grid grid-cols-2 gap-4 pt-4 border-t border-zinc-800">
							<div>
								<div className="text-zinc-400 text-sm mb-1">Total Memory</div>
								<div className="text-zinc-200 font-medium">{formatBytes(systemInfo.total_memory)}</div>
							</div>
							<div>
								<div className="text-zinc-400 text-sm mb-1">Available Memory</div>
								<div className="text-zinc-200 font-medium">{formatBytes(systemInfo.available_memory)}</div>
							</div>
						</div>
					</div>
				</div>

				{/* Process Count */}
				<div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6">
					<h3 className="text-lg font-semibold text-zinc-200 mb-2">Managed Processes</h3>
					<div className="flex items-center gap-4">
						<div className="text-5xl font-bold text-blue-400">{systemInfo.process_count}</div>
						<div className="text-zinc-400 text-sm">
							Total processes currently managed by OPM
						</div>
					</div>
				</div>
			</div>
		</Fragment>
	);
};

export default SystemPage;
