import "server-only";
import { parse, type DefaultTreeAdapterTypes } from "parse5";
import { parse as parseCss, walk } from "css-tree";
import { parseSrcset } from "srcset";

type Element = DefaultTreeAdapterTypes.Element;
export type HtmlInspection = {
  baseUrl: URL;
  formActions: string[];
  hasForms: boolean;
  resourceUrls: string[];
  formIncomplete: boolean;
  resourceIncomplete: boolean;
  generator?: string;
};

const attr = (element: Element, name: string) => element.attrs.find((item) => item.name === name)?.value;
const isElement = (node: DefaultTreeAdapterTypes.Node): node is Element => "tagName" in node;

// Parse the document, never execute scripts or fetch referenced resources.
export function inspectHtml(html: string, documentUrl: URL): HtmlInspection {
  const elements: Element[] = [];
  const pending: DefaultTreeAdapterTypes.Node[] = [...parse(html).childNodes].reverse();
  while (pending.length && elements.length < 50_000) {
    const node = pending.pop()!;
    if (!isElement(node)) continue;
    elements.push(node);
    // Template content is inert; parse5 stores it separately from childNodes.
    if (node.tagName !== "template") {
      for (let index = node.childNodes.length - 1; index >= 0; index -= 1) pending.push(node.childNodes[index]);
    }
  }
  const result: HtmlInspection = {
    baseUrl: documentUrl, formActions: [], hasForms: false, resourceUrls: [],
    formIncomplete: pending.length > 0, resourceIncomplete: pending.length > 0,
  };
  const base = elements.find((node) => node.namespaceURI === "http://www.w3.org/1999/xhtml" && node.tagName === "base" && attr(node, "href") !== undefined);
  if (base) {
    try { result.baseUrl = new URL(attr(base, "href")!, documentUrl); }
    catch { result.formIncomplete = result.resourceIncomplete = true; }
  }
  const forms = elements.filter((node) => node.namespaceURI === "http://www.w3.org/1999/xhtml" && node.tagName === "form");
  result.hasForms = forms.length > 0;
  const ids = new Map<string, Element>();
  for (const element of elements) {
    const id = attr(element, "id");
    if (id && !ids.has(id)) ids.set(id, element);
  }
  const addAction = (value: string) => {
    // Missing or empty action submits to the document, independently of <base>.
    try { result.formActions.push(value ? new URL(value, result.baseUrl).href : documentUrl.href); }
    catch { result.formIncomplete = true; }
  };
  for (const form of forms) {
    if (attr(form, "method")?.toLowerCase() !== "dialog") addAction(attr(form, "action") ?? "");
  }
  for (const node of elements) {
    const tag = node.tagName.toLowerCase();
    if ((tag === "iframe" && attr(node, "srcdoc")) || (tag === "template" && attr(node, "shadowrootmode"))) {
      result.formIncomplete = result.resourceIncomplete = true;
    }
    if (node.namespaceURI === "http://www.w3.org/2000/svg" && ["image", "use", "feimage", "script"].includes(tag)) {
      const href = attr(node, "href");
      if (href && !href.startsWith("#")) result.resourceUrls.push(href);
    }
    const type = attr(node, "type")?.toLowerCase();
    if (node.namespaceURI === "http://www.w3.org/1999/xhtml" && ((tag === "button" && !["button", "reset"].includes(type ?? "")) || (tag === "input" && ["submit", "image"].includes(type ?? "")))) {
      let owner: Element | undefined;
      const ownerId = attr(node, "form");
      if (ownerId !== undefined) owner = ids.get(ownerId);
      else {
        let ancestor = node.parentNode;
        while (ancestor && isElement(ancestor)) {
          if (ancestor.tagName === "form") { owner = ancestor; break; }
          ancestor = ancestor.parentNode;
        }
      }
      if (owner?.tagName === "form" && owner.namespaceURI === "http://www.w3.org/1999/xhtml" && attr(node, "disabled") === undefined
        && (attr(node, "formmethod") ?? attr(owner, "method"))?.toLowerCase() !== "dialog"
        && (attr(node, "formaction") !== undefined || attr(node, "formmethod") !== undefined)) {
        addAction(attr(node, "formaction") ?? attr(owner, "action") ?? "");
      }
    }
    const addResource = (name: string) => {
      const value = attr(node, name);
      if (value?.trim()) result.resourceUrls.push(value);
    };
    if (["script", "img", "iframe", "audio", "video", "source", "track", "embed"].includes(tag)
      || (tag === "input" && type === "image")) addResource("src");
    if (tag === "object") addResource("data");
    if (tag === "video") addResource("poster");
    if (tag === "link" && (attr(node, "rel") ?? "").toLowerCase().split(/\s+/).some((rel) => ["stylesheet", "icon", "preload", "modulepreload", "manifest"].includes(rel))) addResource("href");
    if (["img", "source"].includes(tag) && attr(node, "srcset")) {
      try { result.resourceUrls.push(...parseSrcset(attr(node, "srcset")!, { strict: true }).map((item) => item.url)); }
      catch { result.resourceIncomplete = true; }
    }
    if (tag === "meta" && attr(node, "name")?.toLowerCase() === "generator" && !result.generator) result.generator = attr(node, "content");
    const inspectCss = (css: string, context: "stylesheet" | "declarationList") => {
      if (css.length > 100_000) { result.resourceIncomplete = true; return; }
      try {
        const ast = parseCss(css, { context, parseCustomProperty: true, onParseError: () => { result.resourceIncomplete = true; } });
        walk(ast, function (part) {
          if (part.type === "Declaration" && part.property.startsWith("--")) return this.skip;
          if (part.type === "Function" && part.name.toLowerCase() === "var" && this.declaration
            && /^(?:background|border-image|list-style|cursor|content|mask|filter|clip-path|src|shape-outside|offset-path)/.test(this.declaration.property)) result.resourceIncomplete = true;
          if (part.type === "String" && this.function?.type === "Function" && ["image-set", "-webkit-image-set"].includes(this.function.name)) result.resourceUrls.push(part.value);
          if (part.type === "Url") result.resourceUrls.push(part.value);
          if (part.type === "Atrule" && part.name.toLowerCase() === "import" && part.prelude?.type === "AtrulePrelude") {
            const target = part.prelude.children.first;
            if (target?.type === "String") result.resourceUrls.push(target.value);
          }
          if (part.type === "Raw") result.resourceIncomplete = true;
        });
      } catch { result.resourceIncomplete = true; }
    };
    if (tag === "style") inspectCss(node.childNodes.filter((child) => child.nodeName === "#text").map((child) => (child as DefaultTreeAdapterTypes.TextNode).value).join(""), "stylesheet");
    if (attr(node, "style")) inspectCss(attr(node, "style")!, "declarationList");
  }
  return result;
}
