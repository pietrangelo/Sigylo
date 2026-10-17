import { mount } from 'svelte';
import App from './App.svelte';
import './app.css';
import { language } from './lib/i18n';

document.documentElement.lang = language;
mount(App, { target: document.getElementById('app')! });
