import { render } from 'preact';
import { App } from './app.jsx';
import './styles.css';

/**
 * Application entry point.
 *
 * Mounts the <App/> tree into the `#app` div provided by index.html.
 * The styles import ensures Vite bundles it into `dist/app.css`, served at a
 * fixed path (`GET /app.css`) rather than inlined into the HTML.
 */
render(<App />, document.getElementById('app'));
