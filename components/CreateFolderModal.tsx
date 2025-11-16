import React, { useState, useMemo } from 'react';
import type { BookmarkNode } from '../types';
import { FolderPlusIcon } from './Icons';

interface CreateFolderModalProps {
  onClose: () => void;
  onCreate: (details: { title: string; parentId: string }) => Promise<void>;
  bookmarkTree: BookmarkNode[];
}

const CreateFolderModal: React.FC<CreateFolderModalProps> = ({ onClose, onCreate, bookmarkTree }) => {
  const [title, setTitle] = useState('');
  const [parentId, setParentId] = useState('root-id');
  const [isSaving, setIsSaving] = useState(false);

  const folderOptions = useMemo(() => {
    const options: { label: string, value: string, depth: number }[] = [];
    const traverse = (nodes: BookmarkNode[], depth: number) => {
      nodes.forEach(node => {
        if (node.type === 'folder') {
          options.push({ label: node.title, value: node.id, depth });
          traverse(node.children, depth + 1);
        }
      });
    };
    traverse(bookmarkTree, 0);
    return options;
  }, [bookmarkTree]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || isSaving) return;
    setIsSaving(true);
    await onCreate({ title: title.trim(), parentId });
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="create-folder-title"
    >
      <div
        className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl shadow-2xl p-6 w-full max-w-md m-4"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center mb-4">
            <div className="p-2 bg-blue-100 dark:bg-blue-900/50 rounded-full mr-4">
                <FolderPlusIcon className="h-6 w-6 text-blue-600 dark:text-blue-400" />
            </div>
            <h2 id="create-folder-title" className="text-2xl font-bold text-slate-900 dark:text-slate-100">Create New Folder</h2>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="space-y-4">
            <div>
              <label htmlFor="folder-name" className="block text-sm font-medium text-slate-600 dark:text-slate-300 mb-1">
                Folder Name
              </label>
              <input
                type="text"
                id="folder-name"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                className="w-full bg-slate-100 dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-md py-2 px-3 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition"
                required
                autoFocus
              />
            </div>
            <div>
              <label htmlFor="parent-folder" className="block text-sm font-medium text-slate-600 dark:text-slate-300 mb-1">
                Location
              </label>
              <select 
                id="parent-folder" 
                value={parentId} 
                onChange={(e) => setParentId(e.target.value)} 
                className="w-full bg-slate-100 dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-md py-2 px-3 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition"
              >
                <option value="root-id">Top Level (No Folder)</option>
                {folderOptions.map(folder => (
                  <option key={folder.value} value={folder.value}>
                    {'\u00A0\u00A0'.repeat(folder.depth)}{folder.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="flex justify-end space-x-4 mt-6">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-md bg-slate-200 dark:bg-slate-600 text-slate-800 dark:text-slate-100 hover:bg-slate-300 dark:hover:bg-slate-500 transition"
              disabled={isSaving}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 rounded-md bg-blue-600 text-white hover:bg-blue-500 transition disabled:bg-blue-400 dark:disabled:bg-blue-800 disabled:cursor-not-allowed flex items-center"
              disabled={!title.trim() || isSaving}
            >
              {isSaving ? 'Creating...' : 'Create Folder'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default CreateFolderModal;
