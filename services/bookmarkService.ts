import type { BookmarkNode, BookmarkItem, FolderItem, Bookmark } from '../types';

const browser = (window as any).browser;

const TAG_REGEX = /^((?:\[[^\]]+\]\s*)+)/;

const parseTitleAndTags = (fullTitle: string): { title: string, tags: string[] } => {
  const tagMatch = fullTitle.match(TAG_REGEX);
  if (tagMatch) {
    const tags = tagMatch[1].match(/\[([^\]]+)\]/g)?.map(t => t.slice(1, -1)) || [];
    const title = fullTitle.substring(tagMatch[0].length).trim();
    return { title, tags };
  }
  return { title: fullTitle, tags: [] };
};


const transformBookmarkNode = (node: any): BookmarkNode | null => {
  if (node.url && !node.unmodifiable) {
    const { title, tags } = parseTitleAndTags(node.title || node.url);
    return {
      type: 'bookmark',
      id: node.id,
      title: title,
      url: node.url,
      dateAdded: node.dateAdded,
      tags: tags,
      keyword: node.keyword || undefined,
      parentId: node.parentId,
      index: node.index,
      status: 'unchecked',
      safetyStatus: 'unknown',
    };
  }
  if (node.children) {
    return {
      type: 'folder',
      id: node.id,
      title: node.title || 'Unnamed Folder',
      dateAdded: node.dateAdded,
      parentId: node.parentId,
      index: node.index,
      children: node.children
        .map(transformBookmarkNode)
        .filter((child): child is BookmarkNode => child !== null),
    };
  }
  return null;
};


// --- Stateful Mock Service for Development ---

let mockBookmarkTree: BookmarkNode[] | null = null;

const initializeMockData = (): BookmarkNode[] => [
    { id: 'folder-1', type: 'folder', title: 'Work', parentId: 'root-id', index: 0, children: [
        { id: '1', type: 'bookmark', title: 'React Documentation', url: 'https://react.dev', tags: ['react', 'docs', 'frontend'], keyword: 'react', parentId: 'folder-1', index: 0, status: 'unchecked', safetyStatus: 'unknown' },
        { id: '4', type: 'bookmark', title: 'Mozilla Developer Network', url: 'https://developer.mozilla.org', tags: ['webdev', 'docs'], parentId: 'folder-1', index: 1, status: 'unchecked', safetyStatus: 'unknown' },
    ]},
    { id: 'folder-2', type: 'folder', title: 'Design', parentId: 'root-id', index: 1, children: [
         { id: '2', type: 'bookmark', title: 'Tailwind CSS', url: 'https://tailwindcss.com', tags: ['css', 'utility-first'], parentId: 'folder-2', index: 0, status: 'unchecked', safetyStatus: 'unknown' },
         { id: '6', type: 'bookmark', title: 'Smashing Magazine', url: 'https://www.smashingmagazine.com/', tags: ['design', 'articles', 'ux'], parentId: 'folder-2', index: 1, status: 'unchecked', safetyStatus: 'unknown' },
         // This is a duplicate for testing purposes
         { id: '18', type: 'bookmark', title: 'React Docs (duplicate)', url: 'https://react.dev', tags: ['react', 'duplicate'], parentId: 'folder-2', index: 2, status: 'unchecked', safetyStatus: 'unknown' },
    ]},
    { id: 'folder-3', type: 'folder', title: 'Testing Links', parentId: 'root-id', index: 2, children: [
        { id: '3', type: 'bookmark', title: 'A Dead Link Example', url: 'https://thissitedoesnotexist.com/', tags: ['test', 'broken'], parentId: 'folder-3', index: 0, status: 'unchecked', safetyStatus: 'unknown' },
        { id: '5', type: 'bookmark', title: 'Example of unsafe link', url: 'http://malware.testing.google.test/testing/index.html', tags: ['test', 'security'], parentId: 'folder-3', index: 1, status: 'unchecked', safetyStatus: 'unknown' },
        { id: '11', type: 'bookmark', title: 'A Parked Domain Example', url: 'http://anexampleofaparkedsite.com', tags: ['test', 'parked'], parentId: 'folder-3', index: 2, status: 'unchecked', safetyStatus: 'unknown' },
    ]},
    { id: 'folder-4', type: 'folder', title: 'News & Reading', parentId: 'root-id', index: 3, children: [
        { id: '7', type: 'bookmark', title: 'Hacker News', url: 'https://news.ycombinator.com', tags: ['tech', 'news'], parentId: 'folder-4', index: 0, status: 'unchecked', safetyStatus: 'unknown' },
        { id: '8', type: 'bookmark', title: 'Reddit', url: 'https://www.reddit.com', tags: ['social', 'news'], parentId: 'folder-4', index: 1, status: 'unchecked', safetyStatus: 'unknown' },
        { id: '12', type: 'bookmark', title: 'The Verge', url: 'https://www.theverge.com', tags: ['tech', 'news'], parentId: 'folder-4', index: 2, status: 'unchecked', safetyStatus: 'unknown' },
        { id: '13', type: 'bookmark', title: 'Ars Technica', url: 'https://arstechnica.com', tags: ['tech', 'in-depth'], parentId: 'folder-4', index: 3, status: 'unchecked', safetyStatus: 'unknown' },
        { id: '14', type: 'bookmark', title: 'Medium', url: 'https://medium.com', tags: ['articles', 'writing'], parentId: 'folder-4', index: 4, status: 'unchecked', safetyStatus: 'unknown' },
        { id: '15', type: 'bookmark', title: 'The Atlantic', url: 'https://www.theatlantic.com', tags: ['longform', 'journalism'], parentId: 'folder-4', index: 5, status: 'unchecked', safetyStatus: 'unknown' },
        { id: '16', type: 'bookmark', title: 'NPR', url: 'https://www.npr.org', tags: ['news', 'radio'], parentId: 'folder-4', index: 6, status: 'unchecked', safetyStatus: 'unknown' },
        { id: '17', type: 'bookmark', title: 'Reuters', url: 'https://www.reuters.com', tags: ['world', 'news'], parentId: 'folder-4', index: 7, status: 'unchecked', safetyStatus: 'unknown' },
        { id: 'folder-5', type: 'folder', title: 'Subfolder Example', parentId: 'folder-4', index: 8, children: [
            { id: '9', type: 'bookmark', title: 'A List Apart', url: 'https://alistapart.com/', tags: ['webdev', 'articles'], parentId: 'folder-5', index: 0, status: 'unchecked', safetyStatus: 'unknown' },
        ]},
    ]},
    { id: '10', type: 'bookmark', title: 'GitHub', url: 'https://github.com', tags: ['code', 'hosting'], keyword: 'gh', parentId: 'root-id', index: 4, status: 'unchecked', safetyStatus: 'unknown' },
    {
        id: 'folder-large',
        type: 'folder',
        title: 'Large Folder (100 Bookmarks)',
        parentId: 'root-id',
        index: 5,
        children: Array.from({ length: 100 }, (_, i) => ({
            id: `large-bm-${i + 1}`,
            type: 'bookmark',
            title: `Bookmark Item #${i + 1}`,
            url: `https://example.com/large-item/${i + 1}`,
            tags: ['test-data', 'large-folder'],
            parentId: 'folder-large',
            index: i,
            status: 'unchecked',
            safetyStatus: 'unknown',
        })),
    },
];

const getMockData = () => {
    if (!mockBookmarkTree) {
        mockBookmarkTree = initializeMockData();
    }
    // Return a deep copy to prevent direct mutation of the state from outside
    return JSON.parse(JSON.stringify(mockBookmarkTree));
};

const updateMockData = (newTree: BookmarkNode[]) => {
    mockBookmarkTree = newTree;
};


// Helper for mock service to re-index all nodes
const reIndex = (nodes: BookmarkNode[], pId: string = 'root-id'): BookmarkNode[] => {
    return nodes.map((node, i) => {
        const newNode = { ...node, index: i, parentId: pId };
        if (newNode.type === 'folder') {
            newNode.children = reIndex(newNode.children, newNode.id);
        }
        return newNode;
    });
};

// Pure function to insert a node into a tree
const pureInsertNode = (nodes: BookmarkNode[], nodeToInsert: BookmarkNode, parentId: string, index: number): BookmarkNode[] => {
    if (parentId === 'root-id') {
        const newNodes = [...nodes];
        newNodes.splice(index, 0, nodeToInsert);
        return newNodes;
    }
    return nodes.map(node => {
        if (node.type === 'folder') {
            if (node.id === parentId) {
                const newChildren = [...node.children];
                newChildren.splice(index, 0, nodeToInsert);
                return { ...node, children: newChildren };
            }
            return { ...node, children: pureInsertNode(node.children, nodeToInsert, parentId, index) };
        }
        return node;
    });
};

// Pure function to find and remove a node from a tree
const findAndRemoveNode = (nodes: BookmarkNode[], nodeId: string): { tree: BookmarkNode[], foundNode: BookmarkNode | null } => {
    let foundNode: BookmarkNode | null = null;
    const recursiveFind = (currentNodes: BookmarkNode[]): BookmarkNode[] => {
        const result: BookmarkNode[] = [];
        for (const node of currentNodes) {
            if (node.id === nodeId) {
                foundNode = node;
            } else {
                if (node.type === 'folder') {
                    result.push({ ...node, children: recursiveFind(node.children) });
                } else {
                    result.push(node);
                }
            }
        }
        return result;
    };
    const tree = recursiveFind(nodes);
    return { tree, foundNode };
};

export const getAllBookmarks = async (): Promise<BookmarkNode[]> => {
  if (!browser || !browser.bookmarks) {
    console.warn("Bookmarks API not available. Running in a standard browser context with stateful mock data.");
    return getMockData();
  }
  const bookmarkTree = await browser.bookmarks.getTree();
  const transformedTree = bookmarkTree
    .map(transformBookmarkNode)
    .filter((node): node is BookmarkNode => node !== null);
  
  if (transformedTree.length === 1 && transformedTree[0].type === 'folder') {
     return transformedTree[0].children;
  }
  return transformedTree;
};

export const createBookmark = async (details: { parentId: string; index?: number; title: string; url: string; tags: string[]; keyword?: string; }): Promise<BookmarkItem> => {
    const fullTitle = details.tags.length > 0 ? `${details.tags.map(t => `[${t}]`).join(' ')} ${details.title}` : details.title;

    if (!browser || !browser.bookmarks) {
        const tree = getMockData();
        const newBookmark: BookmarkItem = {
            id: `bookmark-${Date.now()}`,
            type: 'bookmark',
            title: details.title,
            tags: details.tags,
            url: details.url,
            keyword: details.keyword,
            parentId: details.parentId,
            index: details.index,
            status: 'unchecked',
            safetyStatus: 'unknown',
        };
        const newTree = pureInsertNode(tree, newBookmark, details.parentId, details.index ?? 0);
        updateMockData(reIndex(newTree));
        return newBookmark;
    }
    const createdNode = await browser.bookmarks.create({
        parentId: details.parentId === 'root-id' ? undefined : details.parentId,
        index: details.index,
        title: fullTitle,
        url: details.url,
    });
    if (details.keyword) {
        await browser.bookmarks.update(createdNode.id, { keyword: details.keyword });
    }
    const fetchedNode = await browser.bookmarks.get(createdNode.id);
    return transformBookmarkNode(fetchedNode[0]) as BookmarkItem;
};


export const createFolder = async (details: { title: string; parentId?: string; index?: number }): Promise<FolderItem> => {
    if (!browser || !browser.bookmarks) {
        const tree = getMockData();
        const newFolder: FolderItem = {
            id: `folder-${Date.now()}`,
            type: 'folder',
            title: details.title,
            children: [],
            parentId: details.parentId || 'root-id',
            index: details.index ?? tree.length,
        };
        const newTree = pureInsertNode(tree, newFolder, details.parentId || 'root-id', details.index ?? 0);
        updateMockData(reIndex(newTree));
        return newFolder;
    }
    const createdNode = await browser.bookmarks.create({
        title: details.title,
        parentId: details.parentId === 'root-id' ? undefined : details.parentId,
        index: details.index,
    });
    return transformBookmarkNode(createdNode) as FolderItem;
};

export const updateBookmark = async (id: string, updates: { title: string; url: string; tags: string[]; keyword?: string }): Promise<Bookmark> => {
   if (!browser || !browser.bookmarks) {
    const tree = getMockData();
    let updatedBookmark: Bookmark | null = null;
    const updateNodeInTree = (nodes: BookmarkNode[]): BookmarkNode[] => {
        return nodes.map(node => {
          if (node.type === 'bookmark' && node.id === id) {
            const newBookmark = { ...node, ...updates, status: 'unchecked', safetyStatus: 'unknown' } as BookmarkItem;
            updatedBookmark = newBookmark;
            return newBookmark;
          }
          if (node.type === 'folder') {
            return { ...node, children: updateNodeInTree(node.children) };
          }
          return node;
        });
      };
    updateMockData(updateNodeInTree(tree));
    if (!updatedBookmark) throw new Error("Bookmark not found in mock data");
    return updatedBookmark;
  }

  const { title, url, tags, keyword } = updates;
  const newTitleWithTags = tags.length > 0 ? `${tags.map(t => `[${t}]`).join(' ')} ${title}` : title;
  const updatedNode = await browser.bookmarks.update(id, { title: newTitleWithTags, url, keyword });
  const { title: cleanTitle, tags: newTags } = parseTitleAndTags(updatedNode.title);

  return {
    id: updatedNode.id,
    title: cleanTitle,
    url: updatedNode.url,
    dateAdded: updatedNode.dateAdded,
    tags: newTags,
    keyword: updatedNode.keyword || undefined,
    parentId: updatedNode.parentId,
    index: updatedNode.index,
    status: 'unchecked',
    safetyStatus: 'unknown',
  };
};

export const updateFolder = async (id: string, newTitle: string): Promise<FolderItem> => {
    if (!browser || !browser.bookmarks) {
        const tree = getMockData();
        let updatedFolder: FolderItem | null = null;
        const updateNodeInTree = (nodes: BookmarkNode[]): BookmarkNode[] => {
            return nodes.map(node => {
                if (node.type === 'folder' && node.id === id) {
                    const newFolder = { ...node, title: newTitle };
                    updatedFolder = newFolder;
                    return newFolder;
                }
                if (node.type === 'folder') {
                    return { ...node, children: updateNodeInTree(node.children) };
                }
                return node;
            });
        };
        updateMockData(updateNodeInTree(tree));
        if (!updatedFolder) throw new Error("Folder not found in mock data");
        return updatedFolder;
    }

    const updatedNode = await browser.bookmarks.update(id, { title: newTitle });
    return transformBookmarkNode(updatedNode) as FolderItem;
};

export const deleteBookmark = async (id: string): Promise<void> => {
   if (!browser || !browser.bookmarks) {
    const tree = getMockData();
    const { tree: newTree } = findAndRemoveNode(tree, id);
    updateMockData(newTree);
    return;
  }
  await browser.bookmarks.remove(id);
};

export const deleteFolder = async (id: string): Promise<void> => {
    if (!browser || !browser.bookmarks) {
        const tree = getMockData();
        const { tree: newTree } = findAndRemoveNode(tree, id);
        updateMockData(newTree);
        return;
    }
    await browser.bookmarks.removeTree(id);
};

export const moveBookmarkOrFolder = async (id: string, parentId: string, index: number): Promise<void> => {
    const dest = { parentId: parentId === 'root-id' ? undefined : parentId, index };
    if (!browser || !browser.bookmarks) {
        let tree = getMockData();
        const { tree: treeWithoutNode, foundNode: nodeToMove } = findAndRemoveNode(tree, id);

        if (!nodeToMove) {
            console.error("Node to move not found in mock data");
            return;
        }

        const treeWithNodeInNewPosition = pureInsertNode(treeWithoutNode, nodeToMove, dest.parentId || 'root-id', dest.index);
        const finalTree = reIndex(treeWithNodeInNewPosition);
        updateMockData(finalTree);
        return;
    }

    await browser.bookmarks.move(id, dest);
};

export const checkLinkStatus = async (url: string): Promise<'live' | 'dead' | 'parked'> => {
  if (!browser || !browser.runtime || !browser.runtime.sendMessage) {
    if (url.includes('thissitedoesnotexist')) return 'dead';
    if (url.includes('anexampleofaparkedsite')) return 'parked';
    if (url.includes('malware.testing')) return 'live';
    return 'live';
  }
  
  try {
    const response = await browser.runtime.sendMessage({ action: "checkLinkStatus", url: url });
    return response?.status || 'dead';
  } catch (error) {
    console.error(`Error checking link status for ${url} via background script:`, error);
    return 'dead';
  }
};


export const checkLinkSafety = async (url: string): Promise<'safe' | 'unsafe'> => {
  return new Promise(resolve => {
    setTimeout(() => {
      const maliciousDomains = ['malware.testing.google.test'];
      try {
        const hostname = new URL(url).hostname;
        if (maliciousDomains.some(domain => hostname.includes(domain))) {
            resolve('unsafe');
        } else {
            resolve('safe');
        }
      } catch (e) {
          resolve('unsafe');
      }
    }, Math.random() * 1500 + 500); 
  });
};