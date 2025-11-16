import React, { useState, useEffect } from 'react';
import { UndoIcon } from './Icons';

interface FloatingUndoButtonProps {
  onUndo: () => void;
}

const FloatingUndoButton: React.FC<FloatingUndoButtonProps> = ({ onUndo }) => {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    // Animate in on mount
    const timer = setTimeout(() => setVisible(true), 100);
    return () => clearTimeout(timer);
  }, []);

  return (
    <div
      className={`fixed bottom-6 right-6 z-[60] transition-all duration-300 ease-in-out ${visible ? 'translate-y-0 opacity-100' : 'translate-y-4 opacity-0'}`}
      role="status"
    >
      <button
        onClick={onUndo}
        className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-full shadow-lg hover:bg-blue-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-slate-900 focus:ring-blue-500 transition-transform hover:scale-105 active:scale-100"
        title="Undo last action"
      >
        <UndoIcon className="w-5 h-5" />
        <span className="text-sm font-semibold">Undo</span>
      </button>
    </div>
  );
};

export default FloatingUndoButton;