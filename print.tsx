import React, { useState, useEffect, useRef } from 'react';
import ReactDOM from 'react-dom/client';
// @ts-ignore
import { Readability } from './vendor/Readability.js';

const browser = (window as any).browser;

const App: React.FC = () => {
    const [article, setArticle] = useState<{ title: string; content: string; } | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const contentRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const params = new URLSearchParams(window.location.search);
        const articleUrl = params.get('url');

        if (!articleUrl) {
            setError('No URL provided to print.');
            setLoading(false);
            return;
        }
        
        const fetchAndParse = async () => {
            try {
                if (!browser || !browser.runtime || !browser.runtime.sendMessage) {
                    throw new Error("This feature requires extension permissions to fetch external pages for printing.");
                }

                const response = await browser.runtime.sendMessage({
                    action: "getPageContent",
                    url: articleUrl
                });

                if (response.error) {
                    throw new Error(response.error);
                }

                const doc = new DOMParser().parseFromString(response.content, 'text/html');
                const reader = new Readability(doc);
                const parsedArticle = reader.parse();

                if (!parsedArticle || !parsedArticle.content) {
                    throw new Error('Could not extract article content for printing.');
                }
                
                setArticle(parsedArticle);
                document.title = parsedArticle.title || 'Print Preview';

            } catch (err: any) {
                setError(err.message || 'Failed to fetch or parse the article for printing.');
            } finally {
                setLoading(false);
            }
        };

        fetchAndParse();
    }, []);

    useEffect(() => {
        if (article && contentRef.current) {
            const printTimeout = setTimeout(() => {
                window.print();
            }, 500); // Small delay to ensure content is rendered

            return () => clearTimeout(printTimeout);
        }
    }, [article]);

    useEffect(() => {
        const handleAfterPrint = () => {
            window.close();
        };

        window.addEventListener('afterprint', handleAfterPrint);
        return () => window.removeEventListener('afterprint', handleAfterPrint);
    }, []);

    if (loading) {
        return (
            <div className="print-hide p-8 text-center text-gray-600">
                <p>Preparing page for printing...</p>
                <p className="text-sm mt-2">The print dialog will open automatically.</p>
            </div>
        );
    }

    if (error) {
        return (
            <div className="print-hide p-8 text-center text-red-700">
                <h2 className="font-bold">Could not prepare page</h2>
                <p>{error}</p>
                <button 
                    onClick={() => window.close()}
                    className="mt-4 px-4 py-2 bg-gray-200 rounded-md"
                >
                    Close
                </button>
            </div>
        );
    }

    return (
        <article ref={contentRef} className="prose prose-lg max-w-none">
            <h1>{article?.title}</h1>
            <div dangerouslySetInnerHTML={{ __html: article?.content || '' }} />
        </article>
    );
};

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error("Could not find root element to mount print app to");
}

const root = ReactDOM.createRoot(rootElement);
root.render(<App />);