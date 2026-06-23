import { useHashRoute } from './router.js';
import { Nav } from './components/Nav.jsx';
import { BackToTop } from './components/BackToTop.jsx';
import { Dashboard } from './screens/Dashboard.jsx';
import { Fleet } from './screens/Fleet.jsx';
import { Routing } from './screens/Routing.jsx';
import { HTTPRouteDetail } from './screens/HTTPRouteDetail.jsx';
import { IngressDetail } from './screens/IngressDetail.jsx';
import { ProxyDetail } from './screens/ProxyDetail.jsx';
import { ControllerDetail } from './screens/ControllerDetail.jsx';
import { GatewayDetail } from './screens/GatewayDetail.jsx';
import { Events } from './screens/Events.jsx';
import { Topology } from './screens/Topology.jsx';

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
  const { screen, params, query } = useHashRoute();

  return (
    <div class="app">
      <Nav activeScreen={screen} />
      <main
        class={`content${screen === 'topology' ? ' content--full' : ''}`}
        id="main-content"
      >
        <ActiveScreen screen={screen} params={params} query={query} />
      </main>
      <BackToTop />
    </div>
  );
}

function ActiveScreen({ screen, params, query }) {
  switch (screen) {
    case 'dashboard':
      return <Dashboard />;

    case 'fleet':
      return <Fleet query={query} />;

    case 'routing':
      return <Routing query={query} />;

    case 'proxy-detail':
      return <ProxyDetail pod={params.pod} query={query} />;

    case 'controller-detail':
      return <ControllerDetail pod={params.pod} />;

    case 'route-detail':
      return params.kind === 'ingress'
        ? <IngressDetail namespace={params.ns} name={params.name} />
        : <HTTPRouteDetail namespace={params.ns} name={params.name} />;

    case 'gateway-detail':
      return <GatewayDetail namespace={params.ns} name={params.name} />;

    case 'events':
      return <Events />;

    case 'topology':
      return <Topology />;

    default:
      return <Dashboard />;
  }
}
