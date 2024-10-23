import { QuartzConfig } from "./quartz/cfg"
import * as Plugin from "./quartz/plugins"

/**
 * Quartz 4.0 Configuration
 *
 * See https://quartz.jzhao.xyz/configuration for more information.
 */
const config: QuartzConfig = {
  configuration: {
    pageTitle: "❄️  eastXueLian's Blog",
    enableSPA: true,
    enablePopovers: true,
    analytics: {
      provider: "plausible",
    },
    locale: "en-US",
    baseUrl: "eastxuelian.nebuu.la",
    ignorePatterns: ["private", "templates", ".obsidian"],
    defaultDateType: "created",
    theme: {
      fontOrigin: "googleFonts",
      cdnCaching: true,
      typography: {
        header: "Schibsted Grotesk",
        body: "Source Sans Pro",
        code: "IBM Plex Mono",
      },

      colors: {
        darkMode: {
          light: "#282828", // background color (dark)
          lightgray: "#3c3836", // frame / inline code background (grey)
          gray: "#8ec07c", // datetime / graphdot (aqua)
          darkgray: "#ebdbb2", // text (fg)
          dark: "#83a598", // title / toc / inline code (blue)
          secondary: "#d3869b", // link (purple)
          tertiary: "#fe8019", // link highlight (orange)
          highlight: "rgba(104, 157, 106, 0.15)", // tag highlight (aqua with transprancy)
        },
        lightMode: {
          light: "#fbf1c7",
          lightgray: "#ebdbb2",
          gray: "#427b58",
          darkgray: "#3c3836",
          dark: "#076678",
          secondary: "#8f3f71",
          tertiary: "#af3a03",
          highlight: "rgba(104, 157, 106, 0.15)",
        },
      },
    },
  },
  plugins: {
    transformers: [
      Plugin.FrontMatter(),
      Plugin.CreatedModifiedDate({
        priority: ["frontmatter", "filesystem"],
      }),
      Plugin.Latex({ renderEngine: "katex" }),
      Plugin.SyntaxHighlighting({
        theme: {
          light: "solarized-light",
          dark: "vitesse-dark",
        },
        keepBackground: true,
      }),
      Plugin.ObsidianFlavoredMarkdown({ enableInHtmlEmbed: false }),
      Plugin.GitHubFlavoredMarkdown(),
      Plugin.TableOfContents(),
      Plugin.CrawlLinks({ markdownLinkResolution: "shortest" }),
      Plugin.Description(),
    ],
    filters: [Plugin.RemoveDrafts()],
    emitters: [
      Plugin.AliasRedirects(),
      Plugin.ComponentResources(),
      Plugin.ContentPage(),
      Plugin.FolderPage(),
      Plugin.TagPage(),
      Plugin.ContentIndex({
        enableSiteMap: true,
        enableRSS: true,
      }),
      Plugin.Assets(),
      Plugin.Static(),
      Plugin.NotFoundPage(),
    ],
  },
}

export default config
