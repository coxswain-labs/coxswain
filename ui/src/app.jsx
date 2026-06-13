import { useHashRoute } from './router.js';
import { Nav } from './components/Nav.jsx';
import { Fleet } from './screens/Fleet.jsx';
import { RouteInspector } from './screens/RouteInspector.jsx';
import { ProxyDetail } from './screens/ProxyDetail.jsx';
import { GatewayDetail } from './screens/GatewayDetail.jsx';
import { Health } from './screens/Health.jsx';
import { Events } from './screens/Events.jsx';
import { Problems } from './screens/Problems.jsx';

/**
 * Root application component.
 *
 * Renders the <Nav> bar and dispatches to the active screen based on the
 * current URL hash. No client-side router library — the hash format is simple
 * enough that a switch is cleaner and carries no bundle cost.
 *
 * All screens are loaded eagerly (single-file output, no code splitting needed).
 */
export function App() {
  const { screen, params } = useHashRoute();

  return (
    <div class="app">
      <Nav activeScreen={screen} />
      <main class="content" id="main-content">
        <ActiveScreen screen={screen} params={params} />
      </main>
    </div>
  );
}

function ActiveScreen({ screen, params }) {
  switch (screen) {
    case 'fleet':
      return <Fleet />;

    case 'proxy-detail':
      return <ProxyDetail pod={params.pod} />;

    case 'route-inspector':
      return (
        <RouteInspector
          kind={params.kind}
          namespace={params.ns}
          name={params.name}
        />
      );

    case 'gateway-detail':
      return <GatewayDetail namespace={params.ns} name={params.name} />;

    case 'health':
      return <Health />;

    case 'events':
      return <Events />;

    case 'problems':
      return <Problems />;

    default:
      return <Fleet />;
  }
}
