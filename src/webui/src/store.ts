import { persistentMap } from '@nanostores/persistent';

export interface SettingsStore {
	token?: string;
	theme?: 'light' | 'dark';
}

export const $settings = persistentMap<SettingsStore>('settings:', {
	theme: 'dark' // Default to dark mode
});
