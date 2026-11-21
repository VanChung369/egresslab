<script lang="ts">
  import { onMount } from 'svelte';
  import {
    createEndpoint,
    createProfile,
    deleteEndpoint,
    deleteProfile,
    getEndpoints,
    getHealth,
    getOverview,
    getProfiles,
    type Health,
    type Overview,
    type ProxyEndpoint,
    type RoutingProfile
  } from '$lib/api';

  type View = 'overview' | 'endpoints' | 'profiles' | 'tunnels' | 'agents';
  let activeView: View = 'overview';
  let loading = true;
  let connected = false;
  let busy = false;
  let light = false;
  let error = '';
  let notice = '';
  let health: Health | null = null;
  let overview: Overview | null = null;
  let profiles: RoutingProfile[] = [];
  let endpoints: ProxyEndpoint[] = [];

  let profileDialog = false;
  let endpointDialog = false;
  let newProfileName = '';
  let newEndpointName = '';
  let newEndpointProtocol: 'socks5' | 'http-connect' = 'socks5';
  let newEndpointPort = 1080;
  let newEndpointProfileID = '';

  const resources: { id: View; label: string; glyph: string }[] = [
    { id: 'overview', label: 'Overview', glyph: '◫' },
    { id: 'endpoints', label: 'Proxy Endpoints', glyph: '↗' },
    { id: 'profiles', label: 'Routing Profiles', glyph: '◇' },
    { id: 'tunnels', label: 'VPN Tunnels', glyph: '⇄' },
    { id: 'agents', label: 'Network Agents', glyph: '▣' }
  ];

  function viewTitle(): string {
    return resources.find((r) => r.id === activeView)?.label || 'EgressLab';
  }
  function profileName(id: string): string {
    return profiles.find((p) => p.id === id)?.name || 'Unknown profile';
  }
  function setView(view: View): void {
    activeView = view;
    error = '';
    notice = '';
  }

  async function refresh(quiet = false): Promise<void> {
    try {
      const [h, o, p, e] = await Promise.all([
        getHealth(),
        getOverview(),
        getProfiles(),
        getEndpoints()
      ]);
      health = h;
      overview = o;
      profiles = p.items;
      endpoints = e.items;
      connected = true;
      if (!quiet) error = '';
    } catch (e) {
      connected = false;
      if (!quiet) error = e instanceof Error ? e.message : 'Unknown connection error';
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(true), 15000);
    return () => window.clearInterval(timer);
  });

  function openProfile(): void {
    newProfileName = '';
    error = '';
    notice = '';
    profileDialog = true;
  }

  function openEndpoint(): void {
    if (profiles.length === 0) {
      activeView = 'profiles';
      openProfile();
      return;
    }
    newEndpointName = '';
    newEndpointProtocol = 'socks5';
    newEndpointPort = 1080;
    while (endpoints.some((p) => p.port === newEndpointPort) && newEndpointPort < 65535)
      newEndpointPort++;
    newEndpointProfileID = profiles[0].id;
    error = '';
    notice = '';
    endpointDialog = true;
  }

  async function saveProfile(): Promise<void> {
    if (busy) return;
    busy = true;
    error = '';
    try {
      await createProfile(newProfileName);
      profileDialog = false;
      notice = 'Routing profile created. It remains unconfigured and cannot route traffic.';
      await refresh();
    } catch (e) {
      error = e instanceof Error ? e.message : 'Could not save profile';
    } finally {
      busy = false;
    }
  }

  async function saveEndpoint(): Promise<void> {
    if (busy) return;
    busy = true;
    error = '';
    try {
      await createEndpoint({
        name: newEndpointName,
        protocol: newEndpointProtocol,
        profile_id: newEndpointProfileID,
        port: newEndpointPort
      });
      endpointDialog = false;
      activeView = 'endpoints';
      notice =
        'Proxy endpoint saved as a draft. Network activation is blocked until route verification is implemented.';
      await refresh();
    } catch (e) {
      error = e instanceof Error ? e.message : 'Could not save endpoint';
    } finally {
      busy = false;
    }
  }

  async function removeEndpoint(item: ProxyEndpoint): Promise<void> {
    if (!window.confirm(`Delete draft endpoint "${item.name}"?`)) return;
    try {
      await deleteEndpoint(item.id);
      notice = `Deleted ${item.name}.`;
      error = '';
      await refresh();
    } catch (e) {
      error = e instanceof Error ? e.message : 'Could not delete endpoint';
    }
  }

  async function removeProfile(item: RoutingProfile): Promise<void> {
    if (!window.confirm(`Delete routing profile "${item.name}"?`)) return;
    try {
      await deleteProfile(item.id);
      notice = `Deleted ${item.name}.`;
      error = '';
      await refresh();
    } catch (e) {
      error = e instanceof Error ? e.message : 'Could not delete profile';
    }
  }
</script>

<svelte:head>
  <title>EgressLab — Network Routing &amp; Proxy Studio</title>
  <meta name="description" content="EgressLab desktop network routing workstation" />
</svelte:head>

<div class:light class="app-root">
  <div class="app-shell">
    <aside class="sidebar">
      <div class="brand">
        <span class="brand-mark"><span class="mark-nodes">⬡</span></span>
        <div><strong>EgressLab</strong><small>Network Routing Studio</small></div>
      </div>
      <div class="workspace">
        <span class="workspace-icon">EL</span>
        <span><strong>Local workspace</strong><small>Development</small></span>
      </div>
      <div class="environment">
        <span class:offline={!connected} class="signal"></span>{connected
          ? 'Controller connected'
          : 'Controller offline'}
      </div>

      <div class="nav-caption">WORKSPACE</div>
      <nav aria-label="Main navigation">
        {#each resources as item (item.id)}
          <button
            type="button"
            class:active={activeView === item.id}
            class="nav-item"
            on:click={() => setView(item.id)}
          >
            <span class="nav-glyph">{item.glyph}</span><span>{item.label}</span>
            {#if item.id === 'endpoints' && endpoints.length > 0}<span class="count"
                >{endpoints.length}</span
              >{/if}
          </button>
        {/each}
      </nav>
      <div class="nav-caption separate">COMING LATER</div>
      <div class="nav-disabled">
        <span class="nav-glyph">⌁</span> Network Topology <span class="soon">Later</span>
      </div>
      <div class="nav-disabled">
        <span class="nav-glyph">▥</span> Traffic Monitor <span class="soon">Later</span>
      </div>
      <div class="nav-disabled">
        <span class="nav-glyph">◉</span> IP Intelligence <span class="soon">Later</span>
      </div>
      <div class="nav-disabled">
        <span class="nav-glyph">≡</span> Activity &amp; Logs <span class="soon">Later</span>
      </div>

      <div class="sidebar-foot">
        <div class="foot-line"><span class="dot warning"></span> Network engine not enabled</div>
        <button type="button" class="theme-btn" on:click={() => (light = !light)}
          >{light ? '☾ Dark theme' : '☼ Light theme'}</button
        >
        <small>EgressLab v0.1.0 · Phase 1</small>
      </div>
    </aside>

    <main class="main-area">
      <header class="topbar">
        <span class="breadcrumb"
          >Workspace <span class="slash">/</span> <strong>{viewTitle()}</strong></span
        >
        <div class="top-actions">
          <span class:bad={!connected} class="status-chip"
            ><span class:offline={!connected} class="signal"></span>{connected
              ? 'API online'
              : 'API offline'}</span
          >
          <button
            type="button"
            class="icon-button"
            title="Refresh data"
            aria-label="Refresh data"
            on:click={() => void refresh()}>↻</button
          >
        </div>
      </header>

      <div class="page-scroll">
        <div class="page">
          {#if error}<div role="alert" class="banner critical">
              <strong>Action needed</strong><span>{error}</span><button
                type="button"
                aria-label="Dismiss error"
                on:click={() => (error = '')}>×</button
              >
            </div>{/if}
          {#if notice}<div role="status" class="banner success">
              <strong>Saved</strong><span>{notice}</span><button
                type="button"
                aria-label="Dismiss notice"
                on:click={() => (notice = '')}>×</button
              >
            </div>{/if}

          {#if loading}
            <div class="empty">
              <div class="spinner"></div>
              <h2>Connecting to EgressLab controller</h2>
              <p>Reading local configuration state…</p>
            </div>
          {:else if !connected}
            <div class="empty offline-state">
              <span class="empty-icon">↯</span>
              <h2>Local controller is offline</h2>
              <p>
                Start the Go controller to read and manage real configuration data. The UI does not
                substitute mock network status.
              </p>
              <code>cd services/controller &amp;&amp; go run ./cmd/egresslab-controller</code>
              <button type="button" class="btn primary" on:click={() => void refresh()}
                >Retry connection</button
              >
            </div>
          {:else if activeView === 'overview'}
            <div class="page-header">
              <div>
                <div class="eyebrow">CONTROL PLANE</div>
                <h1>Overview</h1>
                <p>Network resources, routing configuration, and readiness at a glance.</p>
              </div>
              <button type="button" class="btn primary" on:click={openEndpoint}
                >+ Create proxy</button
              >
            </div>
            <div class="metric-grid">
              <div class="metric">
                <span>Proxy endpoints</span><strong>{overview?.proxy_endpoints ?? 0}</strong><small
                  >Saved configurations</small
                >
              </div>
              <div class="metric">
                <span>Routing profiles</span><strong>{overview?.profiles ?? 0}</strong><small
                  >Fail-closed policies</small
                >
              </div>
              <div class="metric">
                <span>Active proxies</span><strong>0</strong><small>Runtime not enabled</small>
              </div>
              <div class="metric">
                <span>Connected VPNs</span><strong>0</strong><small>No tunnel agent connected</small
                >
              </div>
              <div class="metric">
                <span>Verified exit IPs</span><strong>0</strong><small>No egress checks yet</small>
              </div>
              <div class="metric">
                <span>Traffic monitor</span><strong>—</strong><small>Requires network agent</small>
              </div>
            </div>
            <section class="panel warning-panel">
              <div class="panel-title">
                <span class="warning-icon">!</span>
                <div>
                  <h2>Safe by default — no live routing</h2>
                  <p>
                    Configuration management works. Proxy traffic, VPN tunneling, IP uniqueness
                    verification, and the kill-switch are not implemented in this first slice.
                  </p>
                </div>
              </div>
              <div class="steps">
                <div>
                  <span class="step-number done">1</span>
                  <div><strong>Control API &amp; persistence</strong><small>Ready</small></div>
                </div>
                <div>
                  <span class="step-number next">2</span>
                  <div>
                    <strong>Linux agent &amp; isolated networking</strong><small
                      >Next implementation milestone</small
                    >
                  </div>
                </div>
                <div>
                  <span class="step-number">3</span>
                  <div>
                    <strong>Verified SOCKS5 runtime</strong><small
                      >Blocked until network policies are enforced</small
                    >
                  </div>
                </div>
              </div>
            </section>
            <div class="twocol">
              <section class="panel">
                <div class="panel-heading">
                  <h2>Recent endpoints</h2>
                  <button class="text-btn" type="button" on:click={() => setView('endpoints')}
                    >View all →</button
                  >
                </div>
                {#if endpoints.length === 0}<div class="mini-empty">
                    No endpoints configured yet. Create a routing profile first, then an endpoint.
                  </div>
                {:else}<div class="resource-list">
                    {#each endpoints.slice(-4).reverse() as endpoint (endpoint.id)}<div
                        class="resource"
                      >
                        <div>
                          <strong>{endpoint.name}</strong><small
                            >{endpoint.listen_host}:{endpoint.port} · {profileName(
                              endpoint.profile_id
                            )}</small
                          >
                        </div>
                        <span class="pill muted">Draft</span>
                      </div>{/each}
                  </div>{/if}
              </section>
              <section class="panel">
                <div class="panel-heading">
                  <h2>Local environment</h2>
                  <span class="pill muted">Controller only</span>
                </div>
                <div class="fact">
                  <span>Controller version</span><code>{health?.version}</code>
                </div>
                <div class="fact"><span>Runtime platform</span><code>{health?.platform}</code></div>
                <div class="fact"><span>Mode</span><code>{health?.mode}</code></div>
                <div class="fact">
                  <span>Verified route enforcement</span><span class="red-text">Unavailable</span>
                </div>
              </section>
            </div>
          {:else if activeView === 'endpoints'}
            <div class="page-header">
              <div>
                <div class="eyebrow">RESOURCES</div>
                <h1>Proxy Endpoints</h1>
                <p>Local listener definitions. Draft endpoints do not accept connections.</p>
              </div>
              <button class="btn primary" type="button" on:click={openEndpoint}
                >+ Create proxy</button
              >
            </div>
            <div class="panel table-panel">
              <div class="panel-heading">
                <h2>All endpoints <span class="muted-text">({endpoints.length})</span></h2>
                <span class="pill warning">Activation disabled until route verification</span>
              </div>
              {#if endpoints.length === 0}<div class="empty-in-panel">
                  <span class="empty-icon">↗</span>
                  <h2>No proxy endpoints yet</h2>
                  <p>
                    Create a routing profile, then add an endpoint. It will be saved as a draft.
                  </p>
                  <button type="button" class="btn" on:click={openEndpoint}>Create endpoint</button>
                </div>
              {:else}<div class="table-wrap">
                  <table>
                    <thead
                      ><tr
                        ><th>NAME</th><th>PROTOCOL</th><th>LISTEN ADDRESS</th><th
                          >ROUTING PROFILE</th
                        ><th>STATE</th><th class="end">ACTIONS</th></tr
                      ></thead
                    ><tbody>
                      {#each endpoints as endpoint (endpoint.id)}
                        <tr
                          ><td class="table-name"><span class="name-dot"></span>{endpoint.name}</td
                          ><td class="mono">{endpoint.protocol.toUpperCase()}</td><td class="mono"
                            >{endpoint.listen_host}:{endpoint.port}</td
                          ><td>{profileName(endpoint.profile_id)}</td><td
                            ><span class="pill muted">Draft · blocked</span></td
                          ><td class="end"
                            ><button
                              class="btn tiny"
                              type="button"
                              disabled
                              title="Requires verified network isolation">Start</button
                            ><button
                              class="btn tiny ghost danger"
                              type="button"
                              on:click={() => void removeEndpoint(endpoint)}>Delete</button
                            ></td
                          ></tr
                        >
                      {/each}
                    </tbody>
                  </table>
                </div>{/if}
            </div>
          {:else if activeView === 'profiles'}
            <div class="page-header">
              <div>
                <div class="eyebrow">RESOURCES</div>
                <h1>Routing Profiles</h1>
                <p>
                  Each profile requires unique exit IP verification and a kill-switch before traffic
                  may flow.
                </p>
              </div>
              <button class="btn primary" type="button" on:click={openProfile}>+ New profile</button
              >
            </div>
            {#if profiles.length === 0}<div class="empty in-page">
                <span class="empty-icon">◇</span>
                <h2>No routing profiles</h2>
                <p>
                  Create a profile to define an isolated network routing policy. All new profiles
                  start unconfigured and blocked.
                </p>
                <button class="btn primary" type="button" on:click={openProfile}
                  >Create routing profile</button
                >
              </div>
            {:else}<div class="profile-grid">
                {#each profiles as profile (profile.id)}
                  <section class="panel profile-card">
                    <div class="profile-top">
                      <div>
                        <h2>{profile.name}</h2>
                        <small class="mono">{profile.id}</small>
                      </div>
                      <span class="pill warning">Unconfigured</span>
                    </div>
                    <div class="profile-check">
                      <span>Unique egress IP policy</span><span class="good-text">Required</span>
                    </div>
                    <div class="profile-check">
                      <span>Kill-switch enforcement</span><span class="good-text">Required</span>
                    </div>
                    <div class="profile-check">
                      <span>VPN tunnel</span><span class="muted-text">Not assigned</span>
                    </div>
                    <div class="profile-check">
                      <span>Active routing</span><span class="red-text">Blocked</span>
                    </div>
                    <div class="profile-footer">
                      <span
                        >{endpoints.filter((e) => e.profile_id === profile.id).length} endpoints attached</span
                      ><button
                        type="button"
                        class="btn tiny ghost danger"
                        on:click={() => void removeProfile(profile)}>Delete</button
                      >
                    </div>
                  </section>{/each}
              </div>{/if}
          {:else if activeView === 'tunnels'}
            <div class="page-header">
              <div>
                <div class="eyebrow">NETWORK ENGINE</div>
                <h1>VPN Tunnels</h1>
                <p>WireGuard and OpenVPN integration is the next implementation phase.</p>
              </div>
            </div>
            <div class="empty in-page">
              <span class="empty-icon">⇄</span>
              <h2>No tunnel management yet</h2>
              <p>
                We will introduce tunnel import, connection health, egress verification, and
                controlled activation after the Linux network agent exists. No simulated VPN is
                shown as connected.
              </p>
              <span class="pill muted">Planned · Phase 2</span>
            </div>
          {:else if activeView === 'agents'}
            <div class="page-header">
              <div>
                <div class="eyebrow">SYSTEM</div>
                <h1>Network Agents</h1>
                <p>Dedicated network engines for WSL2, Ubuntu VM, and remote Linux.</p>
              </div>
            </div>
            <div class="empty in-page">
              <span class="empty-icon">▣</span>
              <h2>No network agent registered</h2>
              <p>
                The Go control API is running on {health?.platform}, but a privileged Linux network
                agent has not been installed or paired. Agent lifecycle and secure pairing are
                planned for the next milestone.
              </p>
              <span class="pill muted">Pairing unavailable</span>
            </div>
          {/if}
        </div>
      </div>
    </main>
  </div>

  {#if profileDialog}
    <div
      class="modal-backdrop"
      role="presentation"
      on:click={(e) => {
        if (e.target === e.currentTarget) profileDialog = false;
      }}
    >
      <section class="modal" role="dialog" aria-modal="true" aria-labelledby="profile-title">
        <header>
          <div>
            <div class="eyebrow">NEW RESOURCE</div>
            <h2 id="profile-title">Create routing profile</h2>
          </div>
          <button
            class="icon-button"
            type="button"
            aria-label="Close dialog"
            on:click={() => (profileDialog = false)}>×</button
          >
        </header>
        <form on:submit|preventDefault={saveProfile}>
          <label for="profile-name">Profile name</label>
          <input
            id="profile-name"
            bind:value={newProfileName}
            required
            minlength="2"
            maxlength="64"
            placeholder="e.g. US Research"
          />
          <div class="inline-warning">
            All new profiles require a unique verified exit IP and an enforced kill-switch. They
            cannot be activated yet.
          </div>
          {#if error}<p class="form-error" role="alert">{error}</p>{/if}
          <footer>
            <button class="btn" type="button" on:click={() => (profileDialog = false)}
              >Cancel</button
            ><button class="btn primary" type="submit" disabled={busy}
              >{busy ? 'Saving…' : 'Create profile'}</button
            >
          </footer>
        </form>
      </section>
    </div>
  {/if}

  {#if endpointDialog}
    <div
      class="modal-backdrop"
      role="presentation"
      on:click={(e) => {
        if (e.target === e.currentTarget) endpointDialog = false;
      }}
    >
      <section class="modal" role="dialog" aria-modal="true" aria-labelledby="endpoint-title">
        <header>
          <div>
            <div class="eyebrow">NEW RESOURCE</div>
            <h2 id="endpoint-title">Create proxy endpoint</h2>
          </div>
          <button
            class="icon-button"
            type="button"
            aria-label="Close dialog"
            on:click={() => (endpointDialog = false)}>×</button
          >
        </header>
        <form on:submit|preventDefault={saveEndpoint}>
          <label for="endpoint-name">Endpoint name</label>
          <input
            id="endpoint-name"
            bind:value={newEndpointName}
            minlength="2"
            maxlength="64"
            required
            placeholder="e.g. US QA Proxy"
          />
          <div class="form-grid">
            <div>
              <label for="endpoint-proto">Protocol</label><select
                id="endpoint-proto"
                bind:value={newEndpointProtocol}
                ><option value="socks5">SOCKS5</option><option value="http-connect"
                  >HTTP CONNECT</option
                ></select
              >
            </div>
            <div>
              <label for="endpoint-port">Local port</label><input
                id="endpoint-port"
                type="number"
                bind:value={newEndpointPort}
                min="1024"
                max="65535"
                required
              />
            </div>
          </div>
          <label for="endpoint-profile">Routing profile</label>
          <select id="endpoint-profile" bind:value={newEndpointProfileID} required
            >{#each profiles as profile (profile.id)}<option value={profile.id}
                >{profile.name}</option
              >{/each}</select
          >
          <div class="inline-warning">
            <strong>Listen address: 127.0.0.1</strong> · This resource will be saved as a draft. It will
            not accept network connections.
          </div>
          {#if error}<p class="form-error" role="alert">{error}</p>{/if}
          <footer>
            <button class="btn" type="button" on:click={() => (endpointDialog = false)}
              >Cancel</button
            ><button class="btn primary" type="submit" disabled={busy}
              >{busy ? 'Saving…' : 'Save draft endpoint'}</button
            >
          </footer>
        </form>
      </section>
    </div>
  {/if}
</div>
