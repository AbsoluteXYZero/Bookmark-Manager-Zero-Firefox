import React from 'react';
import type { BookmarkNode, BookmarkItem, FolderItem } from '../types';
import BookmarkCard from './BookmarkCard';
import BookmarkFolder from './BookmarkFolder';

type VisibleFields = {
  url: boolean;
  tags: boolean;
  keyword: boolean;
  folder: boolean;
  dateAdded: boolean;
};

interface BookmarkListProps {
  nodes: BookmarkNode[];
  viewMode: 'grid' | 'list' | 'enhanced-list';
  zoomIndex: number;
  gridConfig: string;
  visibleFields: VisibleFields;
  depth?: number;
  parentTitle?: string;
  draggedItem: BookmarkNode | null;
  dragOverInfo: { parentId: string; index: number } | null;
  expandedFolders: Set<string>;
  onToggleFolder: (folderId: string) => void;
  isAncestor: (draggedId: string, potentialParentId: string) => boolean;
  onEdit: (bookmark: BookmarkItem) => void;
  onDelete: (id: string) => void;
  onDeleteFolder: (folder: FolderItem) => void;
  onViewSafetyReport: (bookmark: BookmarkItem) => void;
  onHoverStart: (url: string, element: HTMLElement) => void;
  onHoverEnd: () => void;
  setDraggedItem: (item: BookmarkNode | null) => void;
  setDragOverInfo: (info: { parentId: string; index: number } | null) => void;
  handleDrop: () => void;
}

const BookmarkList: React.FC<BookmarkListProps> = (props) => {
  const { nodes, viewMode, gridConfig, depth = 0, draggedItem, dragOverInfo, setDragOverInfo, handleDrop } = props;

  if (nodes.length === 0 && depth === 0) {
      return (
          <div className="text-center py-10 text-slate-600 dark:text-slate-500">
              <p>No bookmarks found matching your criteria.</p>
          </div>
      );
  }
  
  if (viewMode === 'grid') {
    const folders = nodes.filter(node => node.type === 'folder') as FolderItem[];
    const bookmarks = nodes.filter(node => node.type === 'bookmark') as BookmarkItem[];
    
    return (
      <div className="flex flex-col gap-6">
        {folders.map(folder => (
            <BookmarkFolder 
              key={folder.id} 
              {...props} 
              folder={folder} 
              depth={depth}
              partingDirection={null}
              onDragStart={(item) => props.setDraggedItem(item)}
              onDragEnd={() => { props.setDraggedItem(null); setDragOverInfo(null); }}
              onDragOver={(info) => setDragOverInfo(info)}
              onDrop={handleDrop}
            />
        ))}
        {bookmarks.length > 0 && (
            <div 
              className={`grid ${gridConfig} gap-6`}
              onDragOver={(e) => {
                e.preventDefault();
                const parentId = props.parentTitle ? props.nodes[0]?.parentId : 'root-id';
                if (parentId) {
                  setDragOverInfo({ parentId, index: bookmarks.length });
                }
              }}
              onDrop={handleDrop}
            >
                {bookmarks.map(bookmark => (
                    <BookmarkCard
                        key={bookmark.id}
                        {...props}
                        bookmark={bookmark}
                        depth={depth}
                        partingDirection={null}
                        parentTitle={props.parentTitle}
                        onEdit={() => props.onEdit(bookmark)}
                        onDelete={() => props.onDelete(bookmark.id)}
                        onViewSafetyReport={() => props.onViewSafetyReport(bookmark)}
                        onHoverStart={(e) => props.onHoverStart(bookmark.url, e.currentTarget)}
                        onHoverEnd={props.onHoverEnd}
                        onDragStart={(item) => props.setDraggedItem(item)}
                        onDragEnd={() => { props.setDraggedItem(null); setDragOverInfo(null); }}
                        onDragOver={(info) => setDragOverInfo(info)}
                        onDrop={handleDrop}
                    />
                ))}
            </div>
        )}
      </div>
    );
  }

  const containerClasses = `flex flex-col ${depth > 0 ? 'gap-2' : 'gap-3'}`;

  return (
    <div className={containerClasses}>
      {nodes.map((node) => {
        let partingDirection: 'up' | 'down' | null = null;
        if (draggedItem && dragOverInfo && draggedItem.id !== node.id) {
            const isSameParent = dragOverInfo.parentId === node.parentId;
            if (isSameParent) {
                const dropIndex = dragOverInfo.index;
                const myIndex = node.index ?? -1;
                
                // If I am the item AT the drop index, I need to move DOWN to make space.
                if (myIndex === dropIndex) {
                    partingDirection = 'down';
                }
                // If I am the item just BEFORE the drop index, I need to move UP to make space.
                if (myIndex === dropIndex - 1) {
                    partingDirection = 'up';
                }
            }
        }
        
        const componentProps = {
            ...props,
            depth,
            onDragStart: (item: BookmarkNode) => props.setDraggedItem(item),
            onDragEnd: () => { props.setDraggedItem(null); setDragOverInfo(null); },
            onDragOver: (info: { parentId: string, index: number }) => setDragOverInfo(info),
            onDrop: handleDrop,
        };

        if (node.type === 'folder') {
          return <BookmarkFolder key={node.id} {...componentProps} folder={node} partingDirection={partingDirection} />;
        }
        if (node.type === 'bookmark') {
          return (
            <BookmarkCard
              key={node.id}
              {...componentProps}
              bookmark={node}
              parentTitle={props.parentTitle}
              partingDirection={partingDirection}
              onEdit={() => props.onEdit(node)}
              onDelete={() => props.onDelete(node.id)}
              onViewSafetyReport={() => props.onViewSafetyReport(node)}
              onHoverStart={(e) => props.onHoverStart(node.url, e.currentTarget)}
              onHoverEnd={props.onHoverEnd}
            />
          );
        }
        return null;
      })}
    </div>
  );
};

export default BookmarkList;