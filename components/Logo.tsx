import React from 'react';

export const Logo: React.FC = () => (
  <div className="flex items-center gap-4">
    <div className="flex-shrink-0 w-12 h-12 flex items-center justify-center rounded-xl bg-gradient-to-br from-blue-500 to-indigo-600 shadow-lg">
      <svg
        className="w-7 h-7 text-white"
        viewBox="0 0 24 24"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <path
          d="M17.5 2.5H6.5C5.39543 2.5 4.5 3.39543 4.5 4.5V21.5L12 18.5L19.5 21.5V4.5C19.5 3.39543 18.6046 2.5 17.5 2.5Z"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <circle cx="12" cy="8.5" r="2.5" fill="currentColor" />
      </svg>
    </div>
    <div>
      <h1 className="text-3xl font-bold text-slate-900 dark:text-slate-100 tracking-tight">
        Bookmark Manager Zero
      </h1>
      <p className="text-slate-500 dark:text-slate-400 mt-1">
        A modern interface for your native Firefox bookmarks.
      </p>
    </div>
  </div>
);

export default Logo;
