/* [ZeroLabs] 2026-09-07 4:33 PM - added: one seam for every GitLab call */
// Until now the panel and the worker each talked to GitLab directly from about a
// dozen scattered places, all of them hard-wired to the snippets API. That made
// the storage choice impossible to change without touching every call site.
//
// Everything BMZ needs from GitLab is five operations, so they live here behind
// one interface with two implementations. The reconcile, the attribution lists
// and the deferral dialogs sit above this and do not care where the bytes live.
//
// Why a second backend at all: a snippet is a git repository that GitLab never
// repacks, so every push stores another full copy of bookmarks.json. At roughly
// 900 KB a push that repository passed its allocation after 241 syncs and went
// permanently read-only, reporting only "Repository Error updating the snippet".
// Project repositories get GitLab's housekeeping and draw on the namespace
// allowance instead, which is why a 395 MB project of yours is healthy while a
// 2 MB snippet is not.
//
// Loaded as a classic script so both contexts can share it: importScripts() in
// the service worker, a plain script tag in sidepanel.html.

(function (root) {
  'use strict';

  const API = 'https://gitlab.com/api/v4';

  const KIND_SNIPPET = 'snippet';
  const KIND_PROJECT = 'project';

  // GitLab rejects an "update" for a file that does not exist and a "create" for
  // one that does, on both backends. Callers decide which verb to send, exactly
  // as they already do for the snippets API, so that logic does not move here.

  function encodePath(filePath) {
    return encodeURIComponent(filePath);
  }

  async function readJson(response) {
    const text = await response.text();
    if (!text) return null;
    return JSON.parse(text);
  }

  async function failure(response, what) {
    const body = await response.text();
    throw new Error(`${what} failed: ${response.status} - ${body}`);
  }

  // ---------------------------------------------------------------- snippets

  function snippetBackend(context) {
    const { request, headers } = context;

    return {
      kind: KIND_SNIPPET,

      async list() {
        const response = await request(`${API}/snippets`, { headers: headers() });
        if (!response.ok) await failure(response, 'List snippets');
        const all = await readJson(response);
        return (all || []).map(item => ({ id: item.id, title: item.title }));
      },

      async create({ title, files }) {
        const response = await request(`${API}/snippets`, {
          method: 'POST',
          headers: headers(),
          body: JSON.stringify({ title, visibility: 'private', files })
        });
        if (!response.ok) await failure(response, 'Create snippet');
        const created = await readJson(response);
        return { id: created.id };
      },

      async listFiles(id) {
        const response = await request(`${API}/snippets/${id}`, { headers: headers() });
        if (!response.ok) await failure(response, 'Read snippet');
        const snippet = await readJson(response);
        const files = (snippet && snippet.files) || [];
        return files.map(file => file.path || file.file_name).filter(Boolean);
      },

      // The listing sometimes carries the content inline and sometimes does not,
      // so the raw endpoint is the fallback rather than the first choice.
      async readFile(id, filePath) {
        const response = await request(`${API}/snippets/${id}`, { headers: headers() });
        if (!response.ok) await failure(response, 'Read snippet');
        const snippet = await readJson(response);

        const files = (snippet && snippet.files) || [];
        const match = files.find(file => file.path === filePath || file.file_name === filePath);
        if (!match) return null;
        if (match.content) return match.content;

        const rawUrl = `${API}/snippets/${id}/files/main/${filePath}/raw`;
        const rawResponse = await request(rawUrl, { headers: headers() });
        if (!rawResponse.ok) return null;
        return await rawResponse.text();
      },

      // One PUT names every file, and GitLab rewrites only those, which is what
      // lets a pin change leave bookmarks.json untouched.
      async writeFiles(id, files) {
        const response = await request(`${API}/snippets/${id}`, {
          method: 'PUT',
          headers: headers(),
          body: JSON.stringify({ files })
        });
        return response;
      }
    };
  }

  // ---------------------------------------------------------------- projects

  function projectBackend(context) {
    const { request, headers, branch } = context;
    const ref = branch || 'main';

    return {
      kind: KIND_PROJECT,

      /* [ZeroLabs] 2026-09-07 11:05 PM - edited: only repositories BMZ could write to */
      // min_access_level=30 is Developer, the lowest level that can commit. A
      // repository the user can merely read is useless as a bookmark store, and
      // offering it in a picker only produces a failure two clicks later.
      // Newest activity first, so a repository just created for this sits at the
      // top. per_page is GitLab's maximum; past that the paste field is the way
      // in, which is why it is never replaced by the picker.
      async list() {
        const url = `${API}/projects?membership=true&simple=true&min_access_level=30&order_by=last_activity_at&per_page=100`;
        const response = await request(url, { headers: headers() });
        if (!response.ok) await failure(response, 'List projects');
        const all = await readJson(response);
        return (all || []).map(item => ({ id: item.id, title: item.path_with_namespace }));
      },

      // A project has to exist before it can hold files, and it needs a branch
      // before a commit can target one, which is what the README is for.
      async create({ title, files }) {
        const response = await request(`${API}/projects`, {
          method: 'POST',
          headers: headers(),
          body: JSON.stringify({
            name: title,
            visibility: 'private',
            initialize_with_readme: true,
            description: 'Bookmark storage for Bookmark Manager Zero'
          })
        });
        if (!response.ok) await failure(response, 'Create project');
        const created = await readJson(response);

        if (files && files.length > 0) {
          const seed = files.map(file => ({
            action: 'create',
            file_path: file.file_path,
            content: file.content
          }));
          const seedResponse = await this.writeFiles(created.id, seed);
          if (!seedResponse.ok) await failure(seedResponse, 'Seed project');
        }

        return { id: created.id };
      },

      // Throws rather than returning an empty list, deliberately. Callers use
      // this to decide whether a file needs "create" or "update", and answering
      // "no files" for what was really a network failure makes the next write
      // say create for a file that exists, which GitLab refuses outright.
      // per_page is the maximum GitLab allows. A repository with more than 100
      // entries at its root would truncate this list, BMZ would decide its file
      // does not exist, send "create" for one that does, and GitLab would refuse
      // the whole commit. Unlikely for a bookmark repository, but it is the same
      // failure that made this rewrite necessary, so it is worth naming.
      async listFiles(id) {
        const entries = await this.listEntries(id);
        const blobs = entries.filter(entry => entry.type === 'blob');
        return blobs.map(entry => entry.path);
      },

      /* [ZeroLabs] 2026-09-08 12:40 AM - added: the root as it really is, folders included */
      // listFiles drops directories, because its only job is deciding create
      // against update for two known filenames. The emptiness check cannot use
      // it: a repository whose code all sits under src/ would come back as a
      // lone README and read as empty.
      async listEntries(id) {
        const url = `${API}/projects/${id}/repository/tree?ref=${encodeURIComponent(ref)}&per_page=100`;
        const response = await request(url, { headers: headers() });
        if (!response.ok) await failure(response, 'List project files');
        const entries = await readJson(response);
        return (entries || []).map(entry => ({ path: entry.path, type: entry.type }));
      },

      async readFile(id, filePath) {
        const url = `${API}/projects/${id}/repository/files/${encodePath(filePath)}/raw?ref=${encodeURIComponent(ref)}`;
        const response = await request(url, { headers: headers() });
        if (!response.ok) return null;
        return await response.text();
      },

      // The commits endpoint rather than the files endpoint, on purpose: it takes
      // every file in ONE commit. Writing them one at a time would let a sync land
      // half applied, which the snippets API never allowed.
      async writeFiles(id, files) {
        const actions = files.map(file => ({
          action: file.action,
          file_path: file.file_path,
          content: file.content
        }));

        return await request(`${API}/projects/${id}/repository/commits`, {
          method: 'POST',
          headers: headers(),
          body: JSON.stringify({
            branch: ref,
            commit_message: 'Update bookmarks',
            actions
          })
        });
      }
    };
  }

  // ------------------------------------------------------------- diagnostics

  /* [ZeroLabs] 2026-09-07 10:05 PM - added: name the failure that has no name */
  // A snippet whose repository has passed its allocation answers every write
  // with a 400 and "Repository Error updating the snippet". It says nothing
  // about storage, it never recovers, and reads keep working, so the only
  // outward sign is that devices stop agreeing. This is the signature.
  //
  // It lives here rather than in the panel because the BACKGROUND is where the
  // failing writes actually happen. Two copies of a predicate this specific
  // would drift, and the whole point of it is to recognise one exact string.
  function isStoreFullError(status, body) {
    if (status !== 400) return false;
    return /Repository Error/i.test(String(body || ''));
  }

  /* [ZeroLabs] 2026-09-08 12:40 AM - added: is this repository free for BMZ to use */
  // "Use an empty repository I already made" never checked that it was empty. It
  // only refused when a bookmarks.json was already there, so pointing BMZ at a
  // real project committed bookmarks.json onto its main branch and kept
  // committing there on every sync. Nothing was destroyed, but nobody asked for
  // it either. Pasting a full URL made that unlikely; a dropdown of every
  // repository on the account makes it a mis-tap.
  //
  // A repository BMZ creates is initialised with a README, and the how-to screen
  // tells people to leave that box ticked, so a lone README has to read as empty
  // or the check would fire on the very repositories it is meant to approve. The
  // same goes for a licence or a .gitignore picked up from GitLab's own project
  // template, and for BMZ's own two files.
  //
  // ANY directory counts as content. There is no such thing as a folder that
  // arrived by accident.
  const BOILERPLATE = /^(readme(\.(md|txt|rst|adoc))?|license(\.(md|txt))?|copying|changelog(\.md)?|\.gitignore|\.gitattributes|\.gitkeep)$/i;
  const BMZ_FILES = ['bookmarks.json', 'bmz-meta.json'];

  function contentEntries(entries) {
    return (entries || []).filter(entry => {
      if (entry.type === 'tree') return true;
      if (BMZ_FILES.includes(entry.path)) return false;
      return !BOILERPLATE.test(entry.path);
    });
  }

  // ----------------------------------------------------------------- factory

  // `request` is the caller's existing fetch wrapper, so retry handling, service
  // error popups and auth all stay where they are rather than being duplicated.
  function createStore({ kind, request, headers, branch }) {
    const context = { request, headers, branch };
    if (kind === KIND_PROJECT) return projectBackend(context);
    return snippetBackend(context);
  }

  root.BMZGitLabStore = {
    create: createStore,
    isStoreFullError,
    contentEntries,
    SNIPPET: KIND_SNIPPET,
    PROJECT: KIND_PROJECT
  };
})(typeof self !== 'undefined' ? self : globalThis);