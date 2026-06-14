import { render } from 'preact';
import { App } from './app.jsx';
import './styles.css';

/**
 * Application entry point.
 *
 * Mounts the <App/> tree into the `#app` div provided by index.html.
 * The styles import ensures the CSS is inlined into the single-file output
 * by vite-plugin-singlefile.
 */
render(<App />, document.getElementById('app'));
