import React, { useState, useMemo } from 'react';
import type { BookmarkItem } from '../types';
import { XIcon, DeleteIcon } from './Icons';

interface DuplicateBookmarksModalProps {
    isOpen: boolean;
    onClose: () => void;
    duplicateGroups: Record<string, BookmarkItem[]>;
    folderMap: Map<string, string>;
    onDelete: (items: BookmarkItem[]) => void;
}

const DuplicateGroup: React.FC<{
    bookmarks: BookmarkItem[];
    folderMap: Map<string, string>;
    onDelete: (items: BookmarkItem[]) => void;
}> = ({ bookmarks, folderMap, onDelete }) => {
    const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

    const handleSelect = (id: string) => {
        const newSelectedIds = new Set(selectedIds);
        if (newSelectedIds.has(id)) {
            newSelectedIds.delete(id);
        } else {
            newSelectedIds.add(id);
        }
        setSelectedIds(newSelectedIds);
    };

    const handleDeleteSelected = () => {
        const itemsToDelete = bookmarks.filter(bm => selectedIds.has(bm.id));
        if (itemsToDelete.length > 0) {
            onDelete(itemsToDelete);
            setSelectedIds(new Set()); // Clear selection
        }
    };
    
    const handleDeleteAllButFirst = () => {
        const itemsToDelete = bookmarks.slice(1);
        if (itemsToDelete.length > 0) {
            onDelete(itemsToDelete);
        }
    };
    
    return (
        <div className="bg-slate-100 dark:bg-slate-800/50 p-4 rounded-lg">
            <div className="flex justify-between items-center mb-3">
                <p className="text-xs font-mono text-slate-500 dark:text-slate-400 truncate pr-4" title={bookmarks[0].url}>
                    {bookmarks[0].url}
                </p>
                <div className="flex items-center gap-2">
                     <button
                        onClick={handleDeleteAllButFirst}
                        className="text-xs font-semibold text-blue-600 dark:text-blue-400 hover:underline"
                    >
                        Keep First, Delete Rest
                    </button>
                    <button
                        onClick={handleDeleteSelected}
                        disabled={selectedIds.size === 0}
                        className="px-3 py-1 text-xs font-semibold rounded-md bg-red-600 text-white hover:bg-red-500 disabled:bg-red-400 dark:disabled:bg-red-800/50 disabled:cursor-not-allowed"
                    >
                        Delete Selected
                    </button>
                </div>
            </div>
            <div className="space-y-2">
                {bookmarks.map(bm => (
                    <div key={bm.id} className="flex items-center gap-3 p-2 bg-white dark:bg-slate-700/50 rounded-md">
                        <input
                            type="checkbox"
                            checked={selectedIds.has(bm.id)}
                            onChange={() => handleSelect(bm.id)}
                            className="h-4 w-4 rounded bg-slate-200 dark:bg-slate-600 border-slate-300 dark:border-slate-500 text-blue-500 focus:ring-blue-500 flex-shrink-0"
                        />
                        <div className="flex-grow overflow-hidden">
                            <p className="font-semibold text-sm text-slate-800 dark:text-slate-100 truncate" title={bm.title}>{bm.title}</p>
                            <p className="text-xs text-slate-500 dark:text-slate-400 truncate" title={folderMap.get(bm.parentId || '') || 'Unknown Folder'}>
                                Folder: {folderMap.get(bm.parentId || '') || 'Top Level'}
                            </p>
                        </div>
                        <button onClick={() => onDelete([bm])} className="p-2 rounded-full hover:bg-red-500/10 text-slate-500 dark:text-slate-400 hover:text-red-500" title="Delete this bookmark">
                            <DeleteIcon className="h-4 w-4" />
                        </button>
                    </div>
                ))}
            </div>
        </div>
    );
};


const DuplicateBookmarksModal: React.FC<DuplicateBookmarksModalProps> = ({ isOpen, onClose, duplicateGroups, folderMap, onDelete }) => {
    const duplicateGroupKeys = useMemo(() => Object.keys(duplicateGroups), [duplicateGroups]);
    const totalDuplicates = useMemo(() => duplicateGroupKeys.reduce((sum, key) => sum + duplicateGroups[key].length, 0), [duplicateGroupKeys, duplicateGroups]);

    if (!isOpen) return null;

    return (
        <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
            onClick={onClose}
            role="dialog"
            aria-modal="true"
            aria-labelledby="duplicate-modal-title"
        >
            <div
                className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl shadow-2xl w-full max-w-4xl m-4 flex flex-col h-[90vh]"
                onClick={(e) => e.stopPropagation()}
            >
                <header className="p-4 border-b border-slate-200 dark:border-slate-700 flex justify-between items-center flex-shrink-0">
                    <div>
                        <h2 id="duplicate-modal-title" className="text-xl font-bold text-slate-900 dark:text-slate-100">Duplicate Bookmarks Found</h2>
                        <p className="text-sm text-slate-500 dark:text-slate-400">{duplicateGroupKeys.length} groups with {totalDuplicates} total bookmarks found.</p>
                    </div>
                    <button onClick={onClose} className="p-2 rounded-full hover:bg-slate-200 dark:hover:bg-slate-700">
                        <XIcon className="h-5 w-5 text-slate-600 dark:text-slate-300" />
                    </button>
                </header>
                <main className="p-4 overflow-y-auto flex-grow space-y-4">
                    {duplicateGroupKeys.length > 0 ? (
                        duplicateGroupKeys.map(url => (
                            <DuplicateGroup
                                key={url}
                                bookmarks={duplicateGroups[url]}
                                folderMap={folderMap}
                                onDelete={onDelete}
                            />
                        ))
                    ) : (
                        <div className="text-center py-10 text-slate-500 dark:text-slate-400">
                            <p>No duplicate bookmarks were found. Great job keeping things tidy!</p>
                        </div>
                    )}
                </main>
                 <footer className="p-4 border-t border-slate-200 dark:border-slate-700 flex justify-end flex-shrink-0">
                    <button
                        type="button"
                        onClick={onClose}
                        className="px-4 py-2 rounded-md bg-slate-200 dark:bg-slate-600 text-slate-800 dark:text-slate-100 hover:bg-slate-300 dark:hover:bg-slate-500 transition"
                    >
                        Close
                    </button>
                </footer>
            </div>
        </div>
    );
};

export default DuplicateBookmarksModal;