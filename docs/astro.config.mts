import { defineConfig } from 'astro/config'
import sitemap from '@astrojs/sitemap'
import starlight from '@astrojs/starlight'
import starlightCopyButton from 'starlight-copy-button'
import starlightLinksValidator from 'starlight-links-validator'
import starlightLlmsTxt from 'starlight-llms-txt'
import starlightScrollToTop from 'starlight-scroll-to-top'

const SITE_URL = 'https://acme.docs.astercosm.com'
const SITE_DESCRIPTION =
  'AsterACME 官方文档，覆盖快速开始、验证方式选择、账户与证书管理、续期与 ARI、部署 reload、DNS Provider 自动发布、守护进程与容器运行。'

type SidebarItem = {
	label: string
	translations?: Record<string, string>
	link?: string
	collapsed?: boolean
	items?: SidebarItem[]
}

function assertUniqueSidebarLinks<T extends SidebarItem[]>(sidebar: T): T {
	const seen = new Map<string, string>()

	function visit(items: SidebarItem[] | undefined, section: string) {
		for (const item of items ?? []) {
			if (!item.link || item.link.startsWith('http')) {
				visit(item.items, `${section} / ${item.label}`)
				continue
			}

			const previous = seen.get(item.link)
			if (previous) {
				throw new Error(
					`Duplicate sidebar link: ${item.link} appears in both "${previous}" and "${section} / ${item.label}"`
				)
			}

			seen.set(item.link, section)
			visit(item.items, `${section} / ${item.label}`)
		}
	}

	for (const group of sidebar) {
		visit(group.items, group.label)
	}

	return sidebar
}

const sidebar = assertUniqueSidebarLinks([
	{
		label: '开始',
		translations: { en: 'Start' },
		collapsed: false,
		items: [
			{ label: '开始使用', translations: { en: 'Start Here' }, link: '/start/' },
			{ label: '快速开始', translations: { en: 'Quick Start' }, link: '/start/quick-start/' },
			{ label: '安装', translations: { en: 'Installation' }, link: '/start/install/' }
		]
	},
	{
		label: '使用',
		translations: { en: 'Using' },
		collapsed: true,
		items: [
			{ label: '使用概览', translations: { en: 'Using AsterACME' }, link: '/using/' },
			{ label: '账户管理', translations: { en: 'Accounts' }, link: '/using/accounts/' },
			{ label: '验证方式', translations: { en: 'Validation Methods' }, link: '/using/challenges/' },
			{ label: '签发与恢复', translations: { en: 'Issuance and Recovery' }, link: '/using/issuance/' },
			{ label: '续期与 ARI', translations: { en: 'Renewal and ARI' }, link: '/using/renewal/' },
			{ label: '证书部署', translations: { en: 'Deployment' }, link: '/using/deploy/' },
			{ label: '吊销与本地删除', translations: { en: 'Revocation and Removal' }, link: '/using/revocation/' }
		]
	},
	{
		label: '管理',
		translations: { en: 'Administration' },
		collapsed: true,
		items: [
			{ label: '运维管理', translations: { en: 'Operations' }, link: '/admin/' },
			{ label: 'DNS Provider 自动发布', translations: { en: 'DNS Provider Automation' }, link: '/admin/dns-providers/' },
			{ label: '常驻守护与定时任务', translations: { en: 'Daemon and Scheduling' }, link: '/admin/daemon/' },
			{ label: '容器运行', translations: { en: 'Running the Container' }, link: '/admin/docker/' },
			{ label: '数据目录与备份', translations: { en: 'Data Directory and Backups' }, link: '/admin/data-dir/' }
		]
	},
	{
		label: '参考与项目',
		translations: { en: 'Reference and Project' },
		collapsed: true,
		items: [
			{ label: '参考总览', translations: { en: 'Reference Overview' }, link: '/reference/' },
			{ label: 'CLI 命令参考', translations: { en: 'CLI Reference' }, link: '/reference/cli/' },
			{ label: '常见问题', translations: { en: 'FAQ' }, link: '/reference/faq/' },
			{ label: '关于 AsterACME', translations: { en: 'About AsterACME' }, link: '/reference/about/' }
		]
	}
])

export default defineConfig({
	site: SITE_URL,
	build: { format: 'directory' },
	trailingSlash: 'always',
	integrations: [
		starlight({
			title: 'AsterACME',
			description: SITE_DESCRIPTION,
			plugins: [
				starlightCopyButton({
					label: '复制本页 / Copy page',
					successLabel: '已复制 / Copied',
					errorLabel: '复制失败 / Copy failed',
					stateDuration: 1800,
					iconOnly: true
				}),
				starlightLinksValidator({ errorOnRelativeLinks: false }),
				starlightLlmsTxt(),
				starlightScrollToTop({
					position: 'right',
					tooltipText: {
						'zh-CN': '返回顶部',
						en: 'Scroll to top'
					},
					smoothScroll: true,
					threshold: 300,
					borderRadius: '50',
					showProgressRing: true,
					progressRingColor: 'var(--sl-color-accent)',
					showOnHomepage: true
				})
			],
			logo: {
				light: './src/assets/asteracme-dark.svg',
				dark: './src/assets/asteracme-light.svg',
				replacesTitle: true
			},
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/AsterCommunity/AsterACME' }],
			defaultLocale: 'root',
			locales: {
				root: { label: '简体中文', lang: 'zh-CN' },
				en: { label: 'English', lang: 'en' }
			},
			editLink: {
				baseUrl: 'https://github.com/AsterCommunity/AsterACME/edit/main/docs/'
			},
			lastUpdated: true,
			customCss: ['./src/styles/custom.css'],
			expressiveCode: {
				themes: ['vitesse-dark', 'vitesse-light']
			},
			head: [
				{ tag: 'meta', attrs: { name: 'theme-color', content: '#0E1424' } },
				{ tag: 'link', attrs: { rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' } },
				{ tag: 'meta', attrs: { name: 'twitter:card', content: 'summary' } }
			],
			sidebar
		}),
		sitemap()
	]
})
