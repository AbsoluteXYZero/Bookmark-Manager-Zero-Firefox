import React from 'react';
import type { FolderItem } from '../types';
import { AlertTriangleIcon } from './Icons';

// FIX: Update onConfirm to expect a Promise to handle asynchronous deletion correctly.
interface ConfirmFolderDeleteModalProps {
  folder: FolderItem;
  onClose: () => void;
  onConfirm: () => Promise<void>;
}

const countDescendants = (folder: FolderItem): number => {
    let count = folder.children.length;
    folder.children.forEach(child => {
        if (child.type === 'folder') {
            count += countDescendants(child);
        }
    });
    return count;
};

const ConfirmFolderDeleteModal: React.FC<ConfirmFolderDeleteModalProps> = ({ folder, onClose, onConfirm }) => {
  const [isDeleting, setIsDeleting] = React.useState(false);
  const totalItems = countDescendants(folder);

  // FIX: Make the handler async and await the onConfirm call.
  const handleConfirmClick = async () => {
    setIsDeleting(true);
    await onConfirm();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="confirm-folder-delete-title"
    >
      <div
        className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl shadow-2xl p-6 w-full max-w-lg m-4"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center mb-4">
          <div className="p-2 bg-red-100 dark:bg-red-900/50 rounded-full mr-4">
            <AlertTriangleIcon className="h-6 w-6 text-red-600 dark:text-red-400" />
          </div>
          <h2 id="confirm-folder-delete-title" className="text-2xl font-bold text-slate-900 dark:text-slate-100">Delete Folder and Contents?</h2>
        </div>
        <p className="text-slate-600 dark:text-slate-300 mb-4">
          Are you sure you want to delete the folder <strong className="font-semibold text-slate-800 dark:text-slate-100">"{folder.title}"</strong>?
        </p>
         <p className="text-sm font-semibold text-red-600 dark:text-red-400 bg-red-500/10 p-3 rounded-md mb-6">
            This will permanently delete the folder and all of its contents, including <strong className="font-bold">{totalItems}</strong> bookmark(s) and/or subfolder(s). This action cannot be undone.
        </p>
        <div className="flex justify-end space-x-4">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-md bg-slate-200 dark:bg-slate-600 text-slate-800 dark:text-slate-100 hover:bg-slate-300 dark:hover:bg-slate-500 transition"
            disabled={isDeleting}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleConfirmClick}
            className="px-4 py-2 rounded-md bg-red-600 text-white hover:bg-red-500 transition disabled:bg-red-400 dark:disabled:bg-red-800 disabled:cursor-not-allowed flex items-center"
            disabled={isDeleting}
          >
            {isDeleting ? 'Deleting...' : 'Delete Everything'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default ConfirmFolderDeleteModal;