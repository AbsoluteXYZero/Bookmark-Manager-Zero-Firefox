import React from 'react';
import type { BookmarkItem } from '../types';
import { AlertTriangleIcon } from './Icons';

interface DuplicateWarningModalProps {
  conflictingItem: BookmarkItem;
  folderMap: Map<string, string>;
  onClose: () => void; // "Revert & Edit"
  onDelete: () => void; // "Delete This Bookmark"
  onConfirmSave: () => void; // "Save Anyway"
}

const DuplicateWarningModal: React.FC<DuplicateWarningModalProps> = ({ conflictingItem, folderMap, onClose, onDelete, onConfirmSave }) => {
  const folderPath = folderMap.get(conflictingItem.parentId || '') || 'Top Level';

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
      // Don't close on overlay click, force a choice
      role="dialog"
      aria-modal="true"
      aria-labelledby="duplicate-warning-title"
    >
      <div
        className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl shadow-2xl p-6 w-full max-w-lg m-4"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center mb-4">
          <div className="p-2 bg-yellow-100 dark:bg-yellow-900/50 rounded-full mr-4">
            <AlertTriangleIcon className="h-6 w-6 text-yellow-600 dark:text-yellow-400" />
          </div>
          <h2 id="duplicate-warning-title" className="text-2xl font-bold text-slate-900 dark:text-slate-100">Duplicate Bookmark</h2>
        </div>
        <p className="text-slate-600 dark:text-slate-300 mb-4">
          The URL you entered already exists for the following bookmark:
        </p>
        
        <div className="bg-slate-100 dark:bg-slate-700/50 p-3 rounded-md mb-6">
            <p className="text-sm font-semibold text-slate-800 dark:text-slate-200 truncate" title={conflictingItem.title}>
                {conflictingItem.title}
            </p>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                <span className="font-medium">Existing in folder:</span> {folderPath}
            </p>
        </div>

        <p className="text-sm text-slate-500 dark:text-slate-400 mb-6">
          You can save anyway to create a duplicate, or choose another option.
        </p>
        
        <div className="flex justify-end space-x-4">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-md bg-slate-200 dark:bg-slate-600 text-slate-800 dark:text-slate-100 hover:bg-slate-300 dark:hover:bg-slate-500 transition"
          >
            Revert & Edit
          </button>
          <button
            type="button"
            onClick={onDelete}
            className="px-4 py-2 rounded-md bg-red-600 text-white hover:bg-red-500 transition flex items-center"
          >
            Delete Current
          </button>
           <button
            type="button"
            onClick={onConfirmSave}
            className="px-4 py-2 rounded-md bg-blue-600 text-white hover:bg-blue-500 transition flex items-center"
          >
            Save Anyway
          </button>
        </div>
      </div>
    </div>
  );
};

export default DuplicateWarningModal;