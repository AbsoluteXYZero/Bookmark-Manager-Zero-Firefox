/*
 * Copyright (c) 2010 Arc90 Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * This code is heavily based on Arc90's readability.js (1.7.1)
 * available across the web (e.g., http://code.google.com/p/arc90labs-readability).
 *
 * THIS IS A HEAVILY MODIFIED VERSION OF THE ORIGINAL THAT WAS FORKED FROM
 * THE FIREFOX REPOSITORY AND CONVERTED TO A PLAIN JAVASCRIPT MODULE.
 *
 * SEE THE ORIGINAL FOR COPYRIGHT INFORMATION AND LICENSE.
 */

var REGEXPS = {
    // NOTE: These two regular expressions are duplicated in
    // Readability-readerable.js. Please keep them in sync.
    "unlikelyCandidates": /-ad-|ai2html|banner|breadcrumbs|combx|comment|community|cover-wrap|disqus|extra|footer|gdpr|header|legends|menu|related|remark|replies|rss|shoutbox|sidebar|skyscraper|social|sponsor|supplemental|ad-break|agegate|pagination|pager|popup|yom-remote/i,
    "okMaybeItsACandidate": /and|article|body|column|content|main|shadow/i,
  
    "positive": /article|body|content|entry|hentry|h-entry|main|page|pagination|post|text|blog|story/i,
    "negative": /-ad-|hidden|^hid$|hid$|hid\s|hid\s\d|ai2html|banner|combx|comment|com-|contact|foot|footer|footnote|gdpr|masthead|media|meta|outbrain|promo|related|scroll|shoutbox|sidebar|skyscraper|sponsor|shopping|tags|tool|widget/i,
    "extraneous": /print|archive|comment|disqus|email|share|reply|all|login|sign|single|utility/i,
    "byline": /byline|author|dateline|writtenby|p-author/i,
    "replaceFonts": /<(\/?)font[^>]*>/gi,
    "normalize": /\s{2,}/g,
    "videos": /\/\/(www\.)?(dailymotion|youtube|youtube-nocookie|player\.vimeo)\.com/i,
    "shareElements": /(\b|_)(share|sharedaddy)(\b|_)/,
    "nextLink": /(next|weiter|continue|>([^\|]|$)|»([^\|]|$))/i,
    "prevLink": /(prev|earl|old|new|<|«)/i,
    "tokenize": /\W+/g,
    "whitespace": /^\s*$/,
    "hasContent": /\S$/,
    "hashUrl": /^#.+/,
    "srcsetUrl": /(\S+)(\s+[\d.]+[xw])?(\s*(?:,|$))/g,
    "b64DataUrl": /^data:\s*([^\s;,]+)\s*;\s*base64\s*,/i,
    // Commas as used in separators, e.g. "Bob Smith, Red Bar" or "Red Bar, 2017-10-18".
    "commas": /\s*,\s*/,
    // Unlikely things to be div separators. The mdash is because some sites use it as a separator
    // on the same line as the byline, e.g. catégories — Société. The unicode characters
    // are some common separators used on Asian websites.
    "unlikelySeparators": /[|·•—\s\/\\]/g,
  
    "postMessage": /^readability-post-message:/,
  };
  
  function getBody(doc) {
    // If the real body element is empty, maybe we can find a suitable fake body to work on.
    // Some sites created manually a fake body inside the original body, for example:
    // https://www.opennet.ru/opennews/art.shtml?num=52854
    // https://lenta.ru/news/2020/05/13/protest/
    // https://gagadget.com/2020/05/13/sony-anonsirovala-novyij-datchik-izobrazheniya-dlya-smartfonov-s-podderzhkoj-8k-i-rasshirennyim-dinamicheskim-diapazonom/
    if (doc.body && !doc.body.textContent.trim()) {
      let fakeBody;
      // If we're not running in a sandbox, we might have a script that
      // moves the real body to a different place.
      if (doc.documentElement.dataset.contentBody) {
        fakeBody = doc.querySelector(doc.documentElement.dataset.contentBody);
      }
  
      if (!fakeBody && doc.body) {
        // Try to find a fake body element that contains all the page content.
        // Usually it's the first element child of the body.
        let bodyFirstChild = doc.body.firstElementChild;
        if (bodyFirstChild && bodyFirstChild.tagName.toLowerCase() == "body") {
          fakeBody = bodyFirstChild;
        } else {
          // Or we can try to find a main element.
          fakeBody = doc.body.querySelector("main");
        }
      }
  
      if (fakeBody) {
        doc.body.style.display = "none";
        return fakeBody;
      }
    }
    return doc.body;
  }
  
  /**
   * Check if this node has only whitespace and has no sites specific css classname
   * that could be used for content extraction.
   *
   * @param Element
   * @return boolean
   **/
  function isWhitespace(node) {
    // We don't want to remove DOM nodes that have a content-related class name.
    if (node.className && node.className.match(REGEXPS.okMaybeItsACandidate)) {
      return false;
    }
  
    return (node.textContent.trim().length === 0);
  }
  
  function getElementsSrcset(element) {
    if (element.srcset) {
      return element.srcset;
    }
    const sources = element.getElementsByTagName("source");
    for (let i = 0; i < sources.length; i++) {
      if (sources[i].srcset) {
        return sources[i].srcset;
      }
    }
    return null;
  }
  
  function setNodeTag(node, tag) {
    var copy = node.ownerDocument.createElement(tag);
    while (node.firstChild) {
      copy.appendChild(node.firstChild);
    }
    node.parentNode.replaceChild(copy, node);
    node.tagFound = true;
    for (var i = 0; i < node.attributes.length; i++) {
      // It is not possible to set all the attributes of the original node
      // to the new node, because some of them are read only.
      // See: https://developer.mozilla.org/en-US/docs/Web/API/Element/setAttribute#Exceptions
      try {
        copy.setAttribute(node.attributes[i].name, node.attributes[i].value);
      } catch (ex) {
        // For example, the "style" attribute is read only in some cases,
        // so we can skip it.
      }
    }
    return copy;
  }
  
  var _Readability = {
      FLAG_STRIP_UNLIKELYS: 0x1,
      FLAG_WEIGHT_CLASSES: 0x2,
      FLAG_CLEAN_CONDITIONALLY: 0x4,
      FLAG_DISABLE_JSON_LD: 0x8,
      DEFAULT_CHARS_THRESHOLD: 500,
      DEFAULT_N_TOP_CANDIDATES: 5
  };
  
  
  class Readability {
      constructor(doc, options) {
          this.doc = doc;
          this.options = options || {};
      }
  
      parse() {
        var result = this.run();
        //delete this.doc;
        //delete this.options;
        return result;
      }
  
      run() {
          var uri = this.options.uri;
          var flags = this.options.flags;
          var articleTitle;
          var articleByline;
          var articleDir;
          var attempts = [];
          var maxPages = this.options.maxPages || 5;
          var pageNum = 1;
          var shortContent = false;
  
          var body = getBody(this.doc);
  
          if (!body) {
              return null;
          }
  
          // Avoid parsing too large documents, as per configuration.
          if (this.options.maxElemToParse &&
              body.getElementsByTagName("*").length > this.options.maxElemToParse) {
            throw new Error("Aborting parsing document; " + body.getElementsByTagName("*").length +
                            " elements found");
          }
  
          var pageInfo = this._preparer.prepareDocument(this.doc);
  
          if (pageInfo.title) {
            articleTitle = pageInfo.title;
          }
  
          // We now have a clean(ish) body. We won't be messing with the original
          // DOM so let's just make a copy of the original body.
          //
          // You might be wondering why we're doing this since we've already
          // created a clone in prepareDocument(). The answer is that the clone
          // is cheap and we want to preserve the original DOM so the page doesn't
          // change in the user's browser. It's also not something that should be
          // worrying about in the first place.
          //
          // So, not to be cheeky, but the real answer is "because we can".
          var articleContent = this.doc.createElement("DIV");
          articleContent.innerHTML = body.innerHTML;
  
          var result = {
            title: null,
            byline: null,
            dir: null,
            content: null,
            textContent: null,
            length: 0,
            excerpt: null,
            siteName: null
          };
          
          return result;
      }
  }
  
  export { Readability, REGEXPS, _Readability as _ReadabilityForTests };
  