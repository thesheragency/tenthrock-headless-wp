import { cache } from 'react';
import { GraphQLClient, gql } from 'graphql-request';
import type { SeoMetadata, TaxonomyTerm } from '@/shared/schema';
import { rewriteLegacyHref, rewriteLegacyUrlsInText } from '@/lib/config/url-redirects';

// WordPress session cookie cache for preview authentication
// This avoids re-authenticating on every preview request
interface CachedSession {
  cookies: string;
  expiresAt: number;
}

let wpSessionCache: CachedSession | null = null;

// Mutex to prevent multiple simultaneous login attempts
// When Next.js renders a page, it runs generateMetadata and page component in parallel
// Without this lock, both would try to login simultaneously and one might fail
let loginInProgress: Promise<string | null> | null = null;

// Session cache duration: 30 minutes (WordPress session is typically longer, but we refresh early)
const SESSION_CACHE_DURATION_MS = 30 * 60 * 1000;

/**
 * Authenticates with WordPress via /wp-login.php to get session cookies
 * This is needed because:
 * 1. The staging site has HTTP Basic Auth at nginx level (WP_AUTH_USER/WP_AUTH_PASSWORD)
 * 2. WordPress needs separate authentication for draft content access
 * 3. Since both use Basic Auth and we can only send one Authorization header,
 *    we log in via /wp-login.php to get session cookies, then use cookies + staging Basic Auth
 */
async function getWordPressSessionCookies(): Promise<string | null> {
  // Check cache first
  if (wpSessionCache && wpSessionCache.expiresAt > Date.now()) {
    console.log('[Preview Auth] Using cached session cookies');
    return wpSessionCache.cookies;
  }

  // If a login is already in progress, wait for it instead of starting another
  if (loginInProgress) {
    console.log('[Preview Auth] Login already in progress, waiting...');
    return loginInProgress;
  }

  // Start login and store the promise so other callers can wait
  loginInProgress = performWordPressLogin();
  
  try {
    const result = await loginInProgress;
    return result;
  } finally {
    // Clear the in-progress flag when done
    loginInProgress = null;
  }
}

/**
 * Performs the actual WordPress login
 * This is separated from getWordPressSessionCookies to allow for mutex handling
 */
async function performWordPressLogin(): Promise<string | null> {
  // Double-check cache (another request might have populated it while we were waiting)
  if (wpSessionCache && wpSessionCache.expiresAt > Date.now()) {
    console.log('[Preview Auth] Using cached session cookies (after lock)');
    return wpSessionCache.cookies;
  }

  const wpApiUrl = (process.env.WP_API_URL || process.env.WORDPRESS_GRAPHQL_URL);
  const previewUser = process.env.preview_user_un;
  const previewPass = process.env.preview_user_pass;
  
  if (!wpApiUrl || !previewUser || !previewPass) {
    console.warn('[Preview Auth] Missing required credentials: WP_API_URL, preview_user_un, or preview_user_pass');
    return null;
  }

  // Get WordPress base URL (without /graphql)
  const wpBaseUrl = wpApiUrl.replace(/\/graphql\/?$/, '');
  const loginUrl = `${wpBaseUrl}/wp-login.php`;

  console.log('[Preview Auth] Authenticating with WordPress via /wp-login.php');

  try {
    // Build headers with staging Basic Auth to pass nginx
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
    };

    if (process.env.WP_AUTH_USER && process.env.WP_AUTH_PASSWORD) {
      const stagingCredentials = Buffer.from(
        `${process.env.WP_AUTH_USER}:${process.env.WP_AUTH_PASSWORD}`
      ).toString('base64');
      headers['Authorization'] = `Basic ${stagingCredentials}`;
    }

    // POST login form data
    const formData = new URLSearchParams({
      log: previewUser,
      pwd: previewPass,
      'wp-submit': 'Log In',
      redirect_to: `${wpBaseUrl}/wp-admin/`,
      testcookie: '1',
    });

    const response = await fetch(loginUrl, {
      method: 'POST',
      headers,
      body: formData.toString(),
      redirect: 'manual', // Don't follow redirects, we want to capture cookies
    });

    // Extract Set-Cookie headers
    const setCookieHeaders = response.headers.getSetCookie?.() || [];
    
    if (setCookieHeaders.length === 0) {
      // Fallback for environments where getSetCookie isn't available
      const rawCookies = response.headers.get('set-cookie');
      if (rawCookies) {
        setCookieHeaders.push(...rawCookies.split(/,(?=\s*\w+=)/));
      }
    }

    // Filter for WordPress auth cookies (excluding test cookie) and extract cookie values
    const authCookies = setCookieHeaders
      .filter(cookie => 
        (cookie.includes('wordpress_logged_in_') || 
         cookie.includes('wordpress_sec_')) &&
        !cookie.includes('wordpress_test_cookie')
      )
      .map(cookie => cookie.split(';')[0]) // Get just the cookie=value part
      .filter(cookie => cookie.length > 0);

    if (authCookies.length === 0) {
      console.error('[Preview Auth] Login failed - no auth cookies received. Check preview_user_un and preview_user_pass credentials.');
      console.log('[Preview Auth] Response status:', response.status);
      console.log('[Preview Auth] Received cookies:', setCookieHeaders.map(c => c.split('=')[0]).join(', '));
      return null;
    }

    const wpCookies = authCookies.join('; ');

    console.log('[Preview Auth] Successfully authenticated, got session cookies');
    
    // Cache the session cookies
    wpSessionCache = {
      cookies: wpCookies,
      expiresAt: Date.now() + SESSION_CACHE_DURATION_MS,
    };

    return wpCookies;
  } catch (error) {
    console.error('[Preview Auth] Error authenticating with WordPress:', error);
    return null;
  }
}

/**
 * Clears the WordPress session cookie cache
 * Call this if you need to force re-authentication
 */
export function clearWordPressSessionCache(): void {
  wpSessionCache = null;
  console.log('[Preview Auth] Session cache cleared');
}

// WordPress GraphQL client configuration
// Public (non-preview) requests are cached by Next.js for 30 minutes (1800s)
// at the data-fetch layer. This guarantees that no matter how many visitors
// hit how many pages, WordPress is queried at most once per 30 minutes per
// unique GraphQL operation+variables tuple — even for dynamic routes.
export const WP_REVALIDATE_SECONDS = 1800;
export const WP_CACHE_TAG = 'wordpress';

const getWpClient = (authToken?: string) => {
  const wpApiUrl = process.env.WORDPRESS_GRAPHQL_URL || process.env.WP_API_URL;
  
  if (!wpApiUrl) {
    throw new Error('WORDPRESS_GRAPHQL_URL environment variable is not set');
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  // Add Basic Auth if credentials are provided (for staging gate)
  if (process.env.WP_AUTH_USER && process.env.WP_AUTH_PASSWORD) {
    const credentials = Buffer.from(
      `${process.env.WP_AUTH_USER}:${process.env.WP_AUTH_PASSWORD}`
    ).toString('base64');
    headers['Authorization'] = `Basic ${credentials}`;
  }

  // Override with preview token if provided
  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }

  // For preview/auth'd requests, bypass cache so editors see fresh content.
  // For public requests, attach Next.js fetch cache options so identical
  // GraphQL queries within the 30-minute window are served from cache.
  const requestInit: RequestInit = authToken
    ? { cache: 'no-store' as RequestCache }
    : ({
        next: { revalidate: WP_REVALIDATE_SECONDS, tags: [WP_CACHE_TAG] },
      } as unknown as RequestInit);

  return new GraphQLClient(wpApiUrl, {
    headers,
    requestMiddleware: (req) => ({
      ...req,
      ...requestInit,
    }),
  });
};

// WordPress GraphQL client for preview/draft requests with WordPress user authentication
// Uses cookie-based auth to work with staging sites that have nginx Basic Auth
async function getPreviewClient(): Promise<GraphQLClient> {
  const wpApiUrl = (process.env.WP_API_URL || process.env.WORDPRESS_GRAPHQL_URL);
  
  if (!wpApiUrl) {
    throw new Error('WP_API_URL environment variable is not set');
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  // Add staging Basic Auth to pass nginx gate
  if (process.env.WP_AUTH_USER && process.env.WP_AUTH_PASSWORD) {
    const stagingCredentials = Buffer.from(
      `${process.env.WP_AUTH_USER}:${process.env.WP_AUTH_PASSWORD}`
    ).toString('base64');
    headers['Authorization'] = `Basic ${stagingCredentials}`;
  }

  // Get WordPress session cookies for draft content access
  // This is the key to the dual-auth problem:
  // - Basic Auth header passes nginx staging gate
  // - Cookie header authenticates to WordPress for draft access
  const sessionCookies = await getWordPressSessionCookies();
  if (sessionCookies) {
    headers['Cookie'] = sessionCookies;
    console.log('[Preview] Using session cookie authentication');
  } else {
    console.warn('[Preview] No session cookies available - draft content may not be accessible');
  }

  // Preview client must always bypass cache so editors see latest drafts.
  return new GraphQLClient(wpApiUrl, {
    headers,
    requestMiddleware: (req) => ({
      ...req,
      cache: 'no-store' as RequestCache,
    }),
  });
}

// GraphQL fragments for reusable queries
// Note: twitterCardType may not be available in all versions of WPGraphQL Yoast SEO
const SEO_FRAGMENT = gql`
  fragment SeoFields on PostTypeSEO {
    title
    metaDesc
    canonical
    opengraphTitle
    opengraphDescription
    opengraphImage {
      sourceUrl
    }
    opengraphType
    opengraphUrl
    opengraphSiteName
    twitterTitle
    twitterDescription
    twitterImage {
      sourceUrl
    }
    schema {
      raw
    }
  }
`;

const FEATURED_IMAGE_FRAGMENT = gql`
  fragment FeaturedImageFields on MediaItem {
    sourceUrl
    altText
    mediaDetails {
      width
      height
    }
  }
`;

const TAXONOMY_FRAGMENT = gql`
  fragment TaxonomyFields on TermNode {
    databaseId
    name
    slug
    description
    count
  }
`;

// Query for fetching all posts (WordPress default post type)
const GET_POSTS_QUERY = gql`
  ${SEO_FRAGMENT}
  ${FEATURED_IMAGE_FRAGMENT}
  ${TAXONOMY_FRAGMENT}
  query GetPosts($first: Int = 100, $after: String) {
    posts(first: $first, after: $after, where: { status: PUBLISH }) {
      pageInfo {
        hasNextPage
        endCursor
      }
      nodes {
        databaseId
        slug
        title
        content
        excerpt
        status
        date
        modified
        author {
          node {
            name
          }
        }
        featuredImage {
          node {
            ...FeaturedImageFields
          }
        }
        categories {
          nodes {
            ...TaxonomyFields
          }
        }
        tags {
          nodes {
            ...TaxonomyFields
          }
        }
        seo {
          ...SeoFields
        }
      }
    }
  }
`;

// Query for fetching a single post by slug
const GET_POST_BY_SLUG_QUERY = gql`
  ${SEO_FRAGMENT}
  ${FEATURED_IMAGE_FRAGMENT}
  ${TAXONOMY_FRAGMENT}
  query GetPostBySlug($slug: ID!) {
    post(id: $slug, idType: SLUG) {
      databaseId
      slug
      title
      content
      excerpt
      status
      date
      modified
      author {
        node {
          name
        }
      }
      featuredImage {
        node {
          ...FeaturedImageFields
        }
      }
      categories {
        nodes {
          ...TaxonomyFields
        }
      }
      tags {
        nodes {
          ...TaxonomyFields
        }
      }
      seo {
        ...SeoFields
      }
    }
  }
`;

// Query for preview (draft) content by DATABASE_ID
const GET_POST_PREVIEW_QUERY = gql`
  ${SEO_FRAGMENT}
  ${FEATURED_IMAGE_FRAGMENT}
  ${TAXONOMY_FRAGMENT}
  query GetPostPreview($id: ID!) {
    post(id: $id, idType: DATABASE_ID, asPreview: true) {
      databaseId
      slug
      title
      content
      excerpt
      status
      date
      modified
      author {
        node {
          name
        }
      }
      featuredImage {
        node {
          ...FeaturedImageFields
        }
      }
      categories {
        nodes {
          ...TaxonomyFields
        }
      }
      tags {
        nodes {
          ...TaxonomyFields
        }
      }
      seo {
        ...SeoFields
      }
    }
  }
`;

// Query for preview (draft) content by SLUG - used when Draft Mode is enabled
const GET_POST_PREVIEW_BY_SLUG_QUERY = gql`
  ${SEO_FRAGMENT}
  ${FEATURED_IMAGE_FRAGMENT}
  ${TAXONOMY_FRAGMENT}
  query GetPostPreviewBySlug($slug: ID!) {
    post(id: $slug, idType: SLUG, asPreview: true) {
      databaseId
      slug
      title
      content
      excerpt
      status
      date
      modified
      author {
        node {
          name
        }
      }
      featuredImage {
        node {
          ...FeaturedImageFields
        }
      }
      categories {
        nodes {
          ...TaxonomyFields
        }
      }
      tags {
        nodes {
          ...TaxonomyFields
        }
      }
      seo {
        ...SeoFields
      }
    }
  }
`;

// Query for pages
const GET_PAGES_QUERY = gql`
  ${SEO_FRAGMENT}
  query GetPages($first: Int = 100) {
    pages(first: $first, where: { status: PUBLISH }) {
      nodes {
        databaseId
        slug
        title
        content
        status
        modified
        seo {
          ...SeoFields
        }
      }
    }
  }
`;

// Query for page preview
const GET_PAGE_PREVIEW_QUERY = gql`
  ${SEO_FRAGMENT}
  query GetPagePreview($id: ID!) {
    page(id: $id, idType: DATABASE_ID, asPreview: true) {
      databaseId
      slug
      title
      content
      status
      modified
      seo {
        ...SeoFields
      }
    }
  }
`;

// Query for Yoast redirects (requires Yoast SEO Premium with WPGraphQL extension)
const GET_REDIRECTS_QUERY = gql`
  query GetRedirects {
    seo {
      redirects {
        origin
        target
        type
        format
      }
    }
  }
`;

// Query for ACF Global Scripts (requires WPGraphQL for ACF plugin)
// These fields should be registered in ACF Options page with field names:
// - global_head_scripts
// - global_body_scripts
// Note: WPGraphQL exposes the SHER Options page as `sHEROptions` (acronym preserved,
// only the first letter is lowercased). Do NOT change to `sherOptions` — that field
// does not exist on the schema and the query will silently return null.
const GET_ACF_OPTIONS_QUERY = gql`
  query GetAcfOptions {
    sHEROptions {
      globalScripts {
        globalHeadScripts
        globalBodyScripts
      }
    }
  }
`;

const GET_SERVICE_BY_SLUG_QUERY = gql`
  ${SEO_FRAGMENT}
  ${FEATURED_IMAGE_FRAGMENT}
  query GetServiceBySlug($slug: ID!) {
    service(id: $slug, idType: SLUG) {
      databaseId
      slug
      title
      content
      excerpt
      featuredImage {
        node {
          ...FeaturedImageFields
        }
      }
      seo {
        ...SeoFields
      }
      serviceFields {
        heroTitle
        heroDescription
        heroImage
        aboutDescription
        aboutBullets { bulletText }
        subServices { subTitle subDescription subImage subLink subFeatures { featureText } }
        faqs { question answer }
        processSteps { stepNum stepTitle stepDesc }
        stats { statValue statLabel statDescription }
        para1Badge para1Heading para1Body para1Image para1ImageAlt
        para1Bullets { bulletText }
        para2Badge para2Heading para2Body para2Image para2ImageAlt
        para2Bullets { bulletText }
        howItWorksSteps { stepTitle stepDesc }
        ctaImage ctaImageAlt
        processSubtitle
        howItWorksIntro
      }
    }
  }
`;

const GET_INDUSTRY_BY_SLUG_QUERY = gql`
  ${SEO_FRAGMENT}
  ${FEATURED_IMAGE_FRAGMENT}
  query GetIndustryBySlug($slug: ID!) {
    industry(id: $slug, idType: SLUG) {
      databaseId
      slug
      title
      content
      excerpt
      featuredImage {
        node {
          ...FeaturedImageFields
        }
      }
      seo {
        ...SeoFields
      }
      industryFields {
        heroDescription
        heroImage
        aboutTitle
        aboutImage
        aboutBullets { bulletTitle bulletDescription }
        faqs { question answer }
        para1Badge para1Heading para1Body para1Image para1ImageAlt
        para1Bullets { bulletText }
        para2Badge para2Heading para2Body para2Image para2ImageAlt
        para2Bullets { bulletText }
        para3Badge para3Heading para3Body para3Image para3ImageAlt
        para3Bullets { bulletText }
      }
    }
  }
`;

const GET_LOCATION_BY_SLUG_QUERY = gql`
  ${SEO_FRAGMENT}
  ${FEATURED_IMAGE_FRAGMENT}
  query GetLocationBySlug($slug: ID!) {
    location(id: $slug, idType: SLUG) {
      databaseId
      slug
      title
      content
      excerpt
      featuredImage {
        node {
          ...FeaturedImageFields
        }
      }
      seo {
        ...SeoFields
      }
      locationFields {
        heroSubtitle
        heroImage
        aboutDescription
        aboutBullets { bulletText }
        trustedDescription
        infoHeading
        infoBody
        stateAbbreviation
        cities { cityName }
        faqs { question answer }
      }
    }
  }
`;

const GET_ALL_LOCATIONS_QUERY = gql`
  query GetAllLocations {
    locations(first: 100, where: { status: PUBLISH }) {
      nodes {
        slug
      }
    }
  }
`;

const GET_ALL_SERVICES_QUERY = gql`
  query GetAllServices {
    services(first: 100, where: { status: PUBLISH }) {
      nodes {
        slug
      }
    }
  }
`;

const GET_ALL_INDUSTRIES_QUERY = gql`
  query GetAllIndustries {
    industries(first: 100, where: { status: PUBLISH }) {
      nodes {
        slug
      }
    }
  }
`;

const GET_ALL_TESTIMONIALS_QUERY = gql`
  query GetAllTestimonials {
    testimonials(first: 100, where: { status: PUBLISH }) {
      nodes {
        databaseId
        title
        testimonialFields {
          quote
          authorName
          authorRole
          company
          authorImage
        }
      }
    }
  }
`;

const GET_ALL_CASE_STUDIES_QUERY = gql`
  query GetAllCaseStudies {
    caseStudies(first: 100, where: { status: PUBLISH }) {
      nodes {
        databaseId
        title
        caseStudyFields {
          subtitle
          tag
          description
          mainImage
          mainImageAlt
          thumbImages { thumbImage thumbAlt }
          stats { statValue statLabel }
          displayOrder
        }
      }
    }
  }
`;

const GET_ALL_FAQS_QUERY = gql`
  query GetAllFaqs {
    faqs(first: 100, where: { status: PUBLISH }) {
      nodes {
        databaseId
        title
        faqFields {
          answer
          displayOrder
        }
        faqCategories {
          nodes {
            slug
            name
            description
          }
        }
      }
    }
  }
`;

const GET_ALL_PARTNER_LOGOS_QUERY = gql`
  query GetAllPartnerLogos {
    partnerLogos(first: 100, where: { status: PUBLISH }) {
      nodes {
        databaseId
        title
        partnerLogoFields {
          logoImage
          logoAlt
          displayOrder
        }
      }
    }
  }
`;

// Type definitions for WordPress GraphQL responses
interface WpFeaturedImage {
  node: {
    sourceUrl: string;
    altText: string;
    mediaDetails: {
      width: number;
      height: number;
    };
  };
}

interface WpSeo {
  title: string;
  metaDesc: string;
  canonical: string;
  opengraphTitle: string;
  opengraphDescription: string;
  opengraphImage: { sourceUrl: string } | null;
  opengraphType: string;
  opengraphUrl: string;
  opengraphSiteName: string;
  twitterTitle: string;
  twitterDescription: string;
  twitterImage: { sourceUrl: string } | null;
  schema: { raw: string | null } | null;
}

interface WpTaxonomyTerm {
  databaseId: number;
  name: string;
  slug: string;
  description: string;
  count: number;
}

interface WpPost {
  databaseId: number;
  slug: string;
  title: string;
  content: string;
  excerpt: string;
  status: string;
  date: string;
  modified: string;
  author: {
    node: {
      name: string;
    };
  } | null;
  featuredImage: WpFeaturedImage | null;
  categories: {
    nodes: WpTaxonomyTerm[];
  } | null;
  tags: {
    nodes: WpTaxonomyTerm[];
  } | null;
  seo: WpSeo | null;
}

interface WpPage {
  databaseId: number;
  slug: string;
  title: string;
  content: string;
  status: string;
  modified: string;
  seo: WpSeo | null;
}

interface WpRedirect {
  origin: string;
  target: string;
  type: number;
  format: string;
}

interface WpAcfOptions {
  sHEROptions: {
    globalScripts: {
      globalHeadScripts: string | null;
      globalBodyScripts: string | null;
    } | null;
  } | null;
}

export interface GlobalScripts {
  headScripts: string | null;
  bodyScripts: string | null;
}

interface WpCptNode {
  databaseId: number;
  slug: string;
  title: string;
  content: string;
  excerpt: string;
  featuredImage: WpFeaturedImage | null;
  seo: WpSeo | null;
  serviceFields?: WpServiceFields | null;
  industryFields?: WpIndustryFields | null;
  locationFields?: Record<string, unknown> | null;
}

interface WpServiceFields {
  heroTitle: string | null;
  heroDescription: string | null;
  heroImage: string | null;
  aboutDescription: string | null;
  aboutBullets: { bulletText: string }[] | null;
  subServices: {
    subTitle: string;
    subDescription: string;
    subImage: string;
    subLink: string;
    subFeatures: { featureText: string }[] | null;
  }[] | null;
  faqs: { question: string; answer: string }[] | null;
  processSteps: { stepNum: string; stepTitle: string; stepDesc: string }[] | null;
  stats: { statValue: string; statLabel: string; statDescription: string }[] | null;
  para1Badge: string | null;
  para1Heading: string | null;
  para1Body: string | null;
  para1Image: string | null;
  para1ImageAlt: string | null;
  para1Bullets: { bulletText: string }[] | null;
  para2Badge: string | null;
  para2Heading: string | null;
  para2Body: string | null;
  para2Image: string | null;
  para2ImageAlt: string | null;
  para2Bullets: { bulletText: string }[] | null;
  howItWorksSteps: { stepTitle: string; stepDesc: string }[] | null;
  ctaImage: string | null;
  ctaImageAlt: string | null;
  processSubtitle: string | null;
  howItWorksIntro: string | null;
}

interface WpIndustryFields {
  heroDescription: string | null;
  heroImage: string | null;
  aboutTitle: string | null;
  aboutImage: string | null;
  aboutBullets: { bulletTitle: string; bulletDescription: string }[] | null;
  faqs: { question: string; answer: string }[] | null;
  para1Badge: string | null;
  para1Heading: string | null;
  para1Body: string | null;
  para1Image: string | null;
  para1ImageAlt: string | null;
  para1Bullets: { bulletText: string }[] | null;
  para2Badge: string | null;
  para2Heading: string | null;
  para2Body: string | null;
  para2Image: string | null;
  para2ImageAlt: string | null;
  para2Bullets: { bulletText: string }[] | null;
  para3Badge: string | null;
  para3Heading: string | null;
  para3Body: string | null;
  para3Image: string | null;
  para3ImageAlt: string | null;
  para3Bullets: { bulletText: string }[] | null;
}

interface WpTestimonialNode {
  databaseId: number;
  title: string;
  testimonialFields: {
    quote: string;
    authorName: string;
    authorRole: string | null;
    company: string | null;
    authorImage: string | null;
  } | null;
}

interface WpCaseStudyNode {
  databaseId: number;
  title: string;
  caseStudyFields: {
    subtitle: string | null;
    tag: string | null;
    description: string | null;
    mainImage: string | null;
    mainImageAlt: string | null;
    thumbImages: { thumbImage: string; thumbAlt: string }[] | null;
    stats: { statValue: string; statLabel: string }[] | null;
    displayOrder: string | null;
  } | null;
}

interface WpFaqNode {
  databaseId: number;
  title: string;
  faqFields: {
    answer: string;
    displayOrder: string | null;
  } | null;
  faqCategories: {
    nodes: { slug: string; name: string; description?: string }[];
  } | null;
}

interface WpPartnerLogoNode {
  databaseId: number;
  title: string;
  partnerLogoFields: {
    logoImage: string | null;
    logoAlt: string | null;
    displayOrder: string | null;
  } | null;
}

export interface ServiceTemplateData {
  serviceName: string;
  heroTitle?: string;
  serviceDescription: string;
  heroImage?: string;
  aboutDescription?: string;
  aboutBullets?: string[];
  subServices?: {
    title: string;
    description: string;
    image: string;
    link: string;
    features?: string[];
  }[];
  faqs?: { question: string; answer: string }[];
  processSteps?: { num: string; title: string; desc: string }[];
  processSubtitle?: string;
  stats?: { label: string; value: string; description: string }[];
  paragraphSection1?: {
    badge: string;
    heading: string;
    body: string;
    image?: string;
    imageAlt?: string;
    bulletPoints?: string[];
  };
  paragraphSection2?: {
    badge: string;
    heading: string;
    body: string;
    image?: string;
    imageAlt?: string;
    bulletPoints?: string[];
  };
  howItWorksIntro?: string;
  howItWorksSteps?: { title: string; desc: string }[];
  ctaImage?: string;
  ctaImageAlt?: string;
  seoMetadata?: SeoMetadata;
}

export interface IndustryTemplateData {
  industryName: string;
  heroImage: string;
  heroDescription: string;
  aboutTitle: string;
  aboutImage: string;
  bulletPoints: { title: string; description: string }[];
  faqs?: { question: string; answer: string }[];
  paragraphSection1?: {
    badge: string;
    heading: string;
    body: string;
    image?: string;
    imageAlt?: string;
    bulletPoints?: string[];
  };
  paragraphSection2?: {
    badge: string;
    heading: string;
    body: string;
    image?: string;
    imageAlt?: string;
    bulletPoints?: string[];
  };
  paragraphSection3?: {
    badge: string;
    heading: string;
    body: string;
    image?: string;
    imageAlt?: string;
    bulletPoints?: string[];
  };
  seoMetadata?: SeoMetadata;
}

export interface LocationTemplateData {
  locationName: string;
  heroSubtitle: string;
  heroImage: string;
  aboutDescription: string;
  aboutBullets: string[];
  trustedDescription: string;
  infoHeading: string;
  infoBody: string;
  stateAbbreviation: string;
  cities: string[];
  faqs: { question: string; answer: string }[];
  seoMetadata?: SeoMetadata;
}

export interface TestimonialData {
  quote: string;
  author: string;
  role: string;
  company: string;
  img: string;
}

export interface CaseStudyData {
  title: string;
  subtitle: string;
  tag: string;
  description: string;
  mainImage: string;
  mainImageAlt: string;
  thumbImages: { src: string; alt: string }[];
  stats: { value: string; label: string }[];
}

export interface FaqData {
  question: string;
  answer: string;
}

export interface FaqCategoryData {
  id: string;
  label: string;
  description?: string;
  faqs: FaqData[];
}

export interface PartnerLogoData {
  src: string;
  alt: string;
}

export interface CptEntry {
  databaseId: number;
  slug: string;
  title: string;
  content: string;
  excerpt: string;
  featuredImageUrl: string | null;
  featuredImageAlt: string | null;
  seoMetadata?: SeoMetadata;
}

// Rewrite WordPress host -> public site host inside Yoast's JSON-LD schema.
// Yoast emits absolute URLs pointing at the WP origin; for the public site we
// want those same URLs to point at the frontend. We derive the WP origin from
// WORDPRESS_GRAPHQL_URL / WP_API_URL (stripping `/graphql`) and the public
// origin from NEXT_PUBLIC_SITE_URL or SITE_URL (default https://www.tenthrock.com).
const rewriteSchemaHost = (raw: string): string => {
  try {
    const wpEndpoint =
      process.env.WORDPRESS_GRAPHQL_URL || process.env.WP_API_URL || '';
    if (!wpEndpoint) return raw;
    const wpOrigin = new URL(wpEndpoint).origin;
    const siteOrigin = (
      process.env.NEXT_PUBLIC_SITE_URL ||
      process.env.SITE_URL ||
      'https://www.tenthrock.com'
    ).replace(/\/+$/, '');
    if (!wpOrigin || wpOrigin === siteOrigin) return raw;
    // Replace bare origin occurrences; works for both JSON string-escaped and
    // raw forms because Yoast emits the URLs as plain JSON string values.
    return raw.split(wpOrigin).join(siteOrigin);
  } catch {
    return raw;
  }
};

// Transform WordPress SEO data to our schema format
const transformSeoData = (seo: WpSeo | null): SeoMetadata | undefined => {
  if (!seo) return undefined;
  
  const rawSchema = seo.schema?.raw || undefined;
  return {
    title: seo.title,
    metaDesc: seo.metaDesc,
    canonical: seo.canonical ? rewriteLegacyHref(seo.canonical) : seo.canonical,
    opengraphTitle: seo.opengraphTitle,
    opengraphDescription: seo.opengraphDescription,
    opengraphImage: seo.opengraphImage?.sourceUrl,
    opengraphType: seo.opengraphType,
    opengraphUrl: seo.opengraphUrl ? rewriteLegacyHref(seo.opengraphUrl) : seo.opengraphUrl,
    opengraphSiteName: seo.opengraphSiteName,
    twitterTitle: seo.twitterTitle,
    twitterDescription: seo.twitterDescription,
    twitterImage: seo.twitterImage?.sourceUrl,
    // Rewrite host first (WP origin -> public origin), then legacy paths inside
    // every embedded URL so JSON-LD @id/url/breadcrumbs match the new scheme.
    schema: rawSchema
      ? rewriteLegacyUrlsInText(rewriteSchemaHost(rawSchema))
      : undefined,
  };
};

// Transform taxonomy terms to our schema format
const transformTaxonomyTerms = (terms: WpTaxonomyTerm[] | undefined): TaxonomyTerm[] | null => {
  if (!terms || terms.length === 0) return null;
  
  return terms.map(term => ({
    id: term.databaseId,
    name: term.name,
    slug: term.slug,
    description: term.description,
    count: term.count,
  }));
};

// Transform WordPress post to our schema format
export const transformPost = (post: WpPost) => {
  const featuredImage = post.featuredImage?.node;
  
  return {
    wpId: post.databaseId,
    slug: post.slug,
    title: post.title,
    content: post.content,
    excerpt: post.excerpt,
    status: post.status.toLowerCase(),
    author: post.author?.node?.name || null,
    publishedAt: post.date ? new Date(post.date) : null,
    featuredImage: featuredImage?.sourceUrl || null,
    featuredImageAlt: featuredImage?.altText || null,
    categories: transformTaxonomyTerms(post.categories?.nodes),
    tags: transformTaxonomyTerms(post.tags?.nodes),
    seoMetadata: transformSeoData(post.seo),
    isFeatured: false, // Can be determined by category or tag
    wpModified: post.modified ? new Date(post.modified) : null,
  };
};

// Transform WordPress page to our schema format
export const transformPage = (page: WpPage) => {
  return {
    wpId: page.databaseId,
    slug: page.slug,
    title: page.title,
    content: page.content,
    status: page.status.toLowerCase(),
    seoMetadata: transformSeoData(page.seo),
    wpModified: page.modified ? new Date(page.modified) : null,
  };
};

interface PostsResponse {
  posts: {
    pageInfo: { hasNextPage: boolean; endCursor: string };
    nodes: WpPost[];
  };
}

// Fetch all posts from WordPress
export async function fetchPosts(): Promise<ReturnType<typeof transformPost>[]> {
  const client = getWpClient();
  const allPosts: WpPost[] = [];
  let hasNextPage = true;
  let after: string | null = null;

  while (hasNextPage) {
    try {
      const response: PostsResponse = await client.request(GET_POSTS_QUERY, { first: 100, after });

      allPosts.push(...response.posts.nodes);
      hasNextPage = response.posts.pageInfo.hasNextPage;
      after = response.posts.pageInfo.endCursor;
    } catch (error) {
      console.error('Error fetching posts from WordPress:', error);
      throw error;
    }
  }

  return allPosts.map(transformPost);
}

// Fetch a single post by slug
export async function fetchPostBySlug(slug: string): Promise<ReturnType<typeof transformPost> | null> {
  const client = getWpClient();

  try {
    const response = await client.request<{ post: WpPost | null }>(
      GET_POST_BY_SLUG_QUERY,
      { slug }
    );

    if (!response.post) return null;
    return transformPost(response.post);
  } catch (error) {
    console.error('Error fetching post by slug:', error);
    throw error;
  }
}

// Fetch post preview by ID with auth token
export async function fetchPostPreview(
  id: number,
  authToken: string
): Promise<ReturnType<typeof transformPost> | null> {
  const client = getWpClient(authToken);

  try {
    const response = await client.request<{ post: WpPost | null }>(
      GET_POST_PREVIEW_QUERY,
      { id: id.toString() }
    );

    if (!response.post) return null;
    return transformPost(response.post);
  } catch (error) {
    console.error('Error fetching post preview:', error);
    throw error;
  }
}

// Fetch post preview by slug using cookie-based auth (for Draft Mode)
// This fetches draft/revision content directly from WordPress
// Uses staging Basic Auth + WordPress session cookies to work with nginx-protected sites
export async function fetchPostPreviewBySlug(
  slug: string
): Promise<ReturnType<typeof transformPost> | null> {
  console.log('[Preview] Fetching post preview by slug:', slug);
  console.log('[Preview] Using credentials:', process.env.preview_user_un ? 'PREVIEW_USER set' : 'PREVIEW_USER not set');

  try {
    // Get preview client with session cookies (async because it may need to authenticate)
    const client = await getPreviewClient();
    
    const response = await client.request<{ post: WpPost | null }>(
      GET_POST_PREVIEW_BY_SLUG_QUERY,
      { slug }
    );

    console.log('[Preview] Response:', response.post ? 'Post found' : 'Post NOT found');
    
    if (!response.post) return null;
    return transformPost(response.post);
  } catch (error) {
    console.error('[Preview] Error fetching post preview by slug:', error);
    throw error;
  }
}

// Fetch post preview by DATABASE_ID using cookie-based auth (for Draft Mode)
// This is more reliable than slug for draft posts which may not have a proper slug yet
export async function fetchPostPreviewById(
  id: number
): Promise<ReturnType<typeof transformPost> | null> {
  console.log('[Preview] Fetching post preview by ID:', id);

  try {
    // Get preview client with session cookies (async because it may need to authenticate)
    const client = await getPreviewClient();
    
    const response = await client.request<{ post: WpPost | null }>(
      GET_POST_PREVIEW_QUERY,
      { id: id.toString() }
    );

    console.log('[Preview] Response by ID:', response.post ? 'Post found' : 'Post NOT found');
    
    if (!response.post) return null;
    return transformPost(response.post);
  } catch (error) {
    console.error('[Preview] Error fetching post preview by ID:', error);
    throw error;
  }
}

// Fetch all pages from WordPress
export async function fetchPages(): Promise<ReturnType<typeof transformPage>[]> {
  const client = getWpClient();

  try {
    const response = await client.request<{
      pages: { nodes: WpPage[] };
    }>(GET_PAGES_QUERY);

    return response.pages.nodes.map(transformPage);
  } catch (error) {
    console.error('Error fetching pages from WordPress:', error);
    throw error;
  }
}

// Fetch page preview by ID with auth token (legacy)
export async function fetchPagePreview(
  id: number,
  authToken: string
): Promise<ReturnType<typeof transformPage> | null> {
  const client = getWpClient(authToken);

  try {
    const response = await client.request<{ page: WpPage | null }>(
      GET_PAGE_PREVIEW_QUERY,
      { id: id.toString() }
    );

    if (!response.page) return null;
    return transformPage(response.page);
  } catch (error) {
    console.error('Error fetching page preview:', error);
    throw error;
  }
}

// Fetch page preview by DATABASE_ID using cookie-based auth (for Draft Mode)
// This is more reliable than slug for draft pages which may not have a proper slug yet
export async function fetchPagePreviewById(
  id: number
): Promise<ReturnType<typeof transformPage> | null> {
  console.log('[Preview] Fetching page preview by ID:', id);

  try {
    // Get preview client with session cookies (async because it may need to authenticate)
    const client = await getPreviewClient();
    
    const response = await client.request<{ page: WpPage | null }>(
      GET_PAGE_PREVIEW_QUERY,
      { id: id.toString() }
    );

    console.log('[Preview] Page response by ID:', response.page ? 'Page found' : 'Page NOT found');
    
    if (!response.page) return null;
    return transformPage(response.page);
  } catch (error) {
    console.error('[Preview] Error fetching page preview by ID:', error);
    throw error;
  }
}

// Fetch redirects from Redirection plugin (by John Godley)
// Uses custom mu-plugin endpoint for headless access (built-in REST API requires session auth)
export async function fetchRedirects(): Promise<WpRedirect[]> {
  const wpApiUrl = (process.env.WP_API_URL || process.env.WORDPRESS_GRAPHQL_URL);
  if (!wpApiUrl) {
    console.warn('WP_API_URL not set, cannot fetch redirects');
    return [];
  }

  // Get WordPress base URL (without /graphql)
  const wpBaseUrl = wpApiUrl.replace(/\/graphql\/?$/, '');
  const redirectsEndpoint = `${wpBaseUrl}/wp-json/headless/v1/redirects`;

  try {
    // Build request headers with authentication
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (process.env.WP_AUTH_USER && process.env.WP_AUTH_PASSWORD) {
      const credentials = Buffer.from(
        `${process.env.WP_AUTH_USER}:${process.env.WP_AUTH_PASSWORD}`
      ).toString('base64');
      headers['Authorization'] = `Basic ${credentials}`;
    }

    // Cache redirects in the Next.js fetch cache for 30 minutes; tagged so
    // /api/revalidate can purge them along with the rest of WP content.
    const response = await fetch(redirectsEndpoint, {
      headers,
      // @ts-ignore - Next.js extends RequestInit with `next`
      next: { revalidate: WP_REVALIDATE_SECONDS, tags: [WP_CACHE_TAG, 'wordpress-redirects'] },
    });
    
    if (!response.ok) {
      console.warn(`Redirects API returned ${response.status} - mu-plugin may not be installed (see wordpress-plugins/headless-redirects-api.php)`);
      return [];
    }

    const data = await response.json();
    
    // Redirection plugin returns { items: [...] } with each item having:
    // url: source URL, action_data: { url: target }, action_code: redirect type (301, 302, etc.)
    const items = data.items || [];
    
    return items
      .filter((r: { enabled: boolean }) => r.enabled)
      .map((r: { url: string; action_data: { url?: string }; action_code: number }) => ({
        origin: r.url.startsWith('/') ? r.url : `/${r.url}`,
        target: r.action_data?.url || '/',
        type: r.action_code || 301,
        format: 'plain',
      }));
  } catch (error) {
    console.warn('Could not fetch redirects from Redirection plugin:', error);
    return [];
  }
}

// Fetch ACF Global Scripts from Options page
export async function fetchAcfGlobalScripts(): Promise<GlobalScripts> {
  const client = getWpClient();

  try {
    const response = await client.request<WpAcfOptions>(GET_ACF_OPTIONS_QUERY);

    const globalScripts = response.sHEROptions?.globalScripts;
    
    return {
      headScripts: globalScripts?.globalHeadScripts || null,
      bodyScripts: globalScripts?.globalBodyScripts || null,
    };
  } catch (error) {
    // ACF Options may not be configured, return empty
    console.warn('Could not fetch ACF global scripts (ACF Options may not be configured):', error);
    return {
      headScripts: null,
      bodyScripts: null,
    };
  }
}

function transformCptNode(node: WpCptNode): CptEntry {
  return {
    databaseId: node.databaseId,
    slug: node.slug,
    title: node.title,
    content: node.content,
    excerpt: node.excerpt,
    featuredImageUrl: node.featuredImage?.node?.sourceUrl || null,
    featuredImageAlt: node.featuredImage?.node?.altText || null,
    seoMetadata: transformSeoData(node.seo),
  };
}

export async function fetchServiceBySlug(slug: string): Promise<CptEntry | null> {
  const client = getWpClient();
  try {
    const response = await client.request<{ service: WpCptNode | null }>(
      GET_SERVICE_BY_SLUG_QUERY,
      { slug }
    );
    if (!response.service) return null;
    return transformCptNode(response.service);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    if (msg.includes('Cannot query field') || msg.includes('not found')) {
      console.warn(`[WP] Service "${slug}" not found:`, msg);
      return null;
    }
    console.error(`[WP] Failed to fetch service by slug "${slug}":`, error);
    throw error;
  }
}

export async function fetchIndustryBySlug(slug: string): Promise<CptEntry | null> {
  const client = getWpClient();
  try {
    const response = await client.request<{ industry: WpCptNode | null }>(
      GET_INDUSTRY_BY_SLUG_QUERY,
      { slug }
    );
    if (!response.industry) return null;
    return transformCptNode(response.industry);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    if (msg.includes('Cannot query field') || msg.includes('not found')) {
      console.warn(`[WP] Industry "${slug}" not found:`, msg);
      return null;
    }
    console.error(`[WP] Failed to fetch industry by slug "${slug}":`, error);
    throw error;
  }
}

export async function fetchAllServiceSlugs(): Promise<string[]> {
  const client = getWpClient();
  try {
    const response = await client.request<{ services: { nodes: { slug: string }[] } }>(
      GET_ALL_SERVICES_QUERY
    );
    return response.services.nodes.map(n => n.slug);
  } catch (error) {
    console.error('[WP] Failed to fetch service slugs:', error);
    return [];
  }
}

export async function fetchAllIndustrySlugs(): Promise<string[]> {
  const client = getWpClient();
  try {
    const response = await client.request<{ industries: { nodes: { slug: string }[] } }>(
      GET_ALL_INDUSTRIES_QUERY
    );
    return response.industries.nodes.map(n => n.slug);
  } catch (error) {
    console.error('[WP] Failed to fetch industry slugs:', error);
    return [];
  }
}

export async function fetchLocationBySlug(slug: string): Promise<CptEntry | null> {
  const client = getWpClient();
  try {
    const response = await client.request<{ location: WpCptNode | null }>(
      GET_LOCATION_BY_SLUG_QUERY,
      { slug }
    );
    if (!response.location) return null;
    return transformCptNode(response.location);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    if (msg.includes('Cannot query field') || msg.includes('not found')) {
      console.warn(`[WP] Location "${slug}" not found:`, msg);
      return null;
    }
    console.error(`[WP] Failed to fetch location by slug "${slug}":`, error);
    throw error;
  }
}

function parseInfoFromContent(content: string | null): { infoHeading: string; infoBody: string } {
  const defaults = { infoHeading: 'Why Local Businesses Choose Us', infoBody: '' };
  if (!content) return defaults;
  try {
    const cleaned = content
      .replace(/<[^>]*>/g, '')
      .replace(/\u201c/g, '"').replace(/\u201d/g, '"')
      .replace(/&#8220;/g, '"').replace(/&#8221;/g, '"')
      .replace(/&#8217;/g, "'")
      .trim();
    const parsed = JSON.parse(cleaned);
    return {
      infoHeading: parsed.infoHeading || defaults.infoHeading,
      infoBody: parsed.infoBody || defaults.infoBody,
    };
  } catch {
    return defaults;
  }
}

function transformLocationNode(node: WpCptNode): LocationTemplateData {
  const lf = node.locationFields as {
    heroSubtitle?: string;
    heroImage?: string;
    aboutDescription?: string;
    aboutBullets?: { bulletText: string }[];
    trustedDescription?: string;
    infoHeading?: string;
    infoBody?: string;
    stateAbbreviation?: string;
    cities?: { cityName: string }[];
    faqs?: { question: string; answer: string }[];
  } | null;

  const locationName = node.title.replace(/^Waste Management Services in\s*/i, '');
  // Prefer ACF fields; fall back to legacy JSON-in-content for any unmigrated posts.
  const acfHeading = lf?.infoHeading?.trim();
  const acfBody = lf?.infoBody?.trim();
  const legacy = (acfHeading && acfBody) ? null : parseInfoFromContent(node.content);

  return {
    locationName,
    heroSubtitle: lf?.heroSubtitle || '',
    heroImage: lf?.heroImage || '/images/stock/locations-hero-modern-city.webp',
    aboutDescription: lf?.aboutDescription || '',
    aboutBullets: lf?.aboutBullets?.map(b => b.bulletText) || [],
    trustedDescription: lf?.trustedDescription || '',
    infoHeading: acfHeading || legacy?.infoHeading || 'Why Local Businesses Choose Us',
    infoBody: acfBody || legacy?.infoBody || `Commercial waste challenges require fast coordination and dependable service partners. Tenth Rock Waste Solutions works directly with local waste facilities and hauling partners across ${locationName} to coordinate bulk waste removal, site cleanouts, and operational waste disruptions with minimal downtime.`,
    stateAbbreviation: lf?.stateAbbreviation || '',
    cities: lf?.cities?.map(c => c.cityName) || [],
    faqs: lf?.faqs?.length ? lf.faqs : [],
    seoMetadata: transformSeoData(node.seo),
  };
}

export const fetchLocationWithAcf = cache(async (slug: string): Promise<LocationTemplateData | null> => {
  const client = getWpClient();
  try {
    const response = await client.request<{ location: WpCptNode | null }>(
      GET_LOCATION_BY_SLUG_QUERY,
      { slug }
    );
    if (!response.location) return null;
    return transformLocationNode(response.location);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    if (msg.includes('Cannot query field') || msg.includes('not found')) {
      console.warn(`[WP] Location "${slug}" ACF not found:`, msg);
      return null;
    }
    console.error(`[WP] Failed to fetch location with ACF "${slug}":`, error);
    return null;
  }
});

export async function fetchAllLocationSlugs(): Promise<string[]> {
  const client = getWpClient();
  try {
    const response = await client.request<{ locations: { nodes: { slug: string }[] } }>(
      GET_ALL_LOCATIONS_QUERY
    );
    return response.locations.nodes.map(n => n.slug);
  } catch (error) {
    console.error('[WP] Failed to fetch location slugs:', error);
    return [];
  }
}

// Check WordPress connection
export async function checkWordPressConnection(): Promise<boolean> {
  try {
    const client = getWpClient();
    await client.request(gql`
      query HealthCheck {
        generalSettings {
          title
        }
      }
    `);
    return true;
  } catch (error) {
    console.error('WordPress connection check failed:', error);
    return false;
  }
}

function buildParagraphSection(
  badge: string | null,
  heading: string | null,
  body: string | null,
  image: string | null,
  imageAlt: string | null,
  bullets: { bulletText: string }[] | null,
) {
  if (!badge && !heading && !body) return undefined;
  return {
    badge: badge || '',
    heading: heading || '',
    body: body || '',
    image: image || undefined,
    imageAlt: imageAlt || undefined,
    bulletPoints: bullets?.map(b => b.bulletText).filter(Boolean) || undefined,
  };
}

function transformServiceNode(node: WpCptNode): ServiceTemplateData {
  const sf = node.serviceFields;
  const result: ServiceTemplateData = {
    serviceName: node.title,
    serviceDescription: sf?.heroDescription || node.excerpt?.replace(/<[^>]*>/g, '').trim() || node.title,
    seoMetadata: transformSeoData(node.seo),
  };

  if (sf?.heroTitle) result.heroTitle = sf.heroTitle;
  if (sf?.heroImage) result.heroImage = sf.heroImage;
  else if (node.featuredImage?.node?.sourceUrl) result.heroImage = node.featuredImage.node.sourceUrl;
  if (sf?.aboutDescription) result.aboutDescription = sf.aboutDescription;
  if (sf?.aboutBullets?.length) result.aboutBullets = sf.aboutBullets.map(b => b.bulletText).filter(Boolean);
  if (sf?.subServices?.length) {
    result.subServices = sf.subServices.map(s => ({
      title: s.subTitle,
      description: s.subDescription,
      image: s.subImage,
      link: s.subLink,
      features: s.subFeatures?.map(f => f.featureText).filter(Boolean) || undefined,
    }));
  }
  if (sf?.faqs?.length) result.faqs = sf.faqs;
  if (sf?.processSteps?.length) {
    result.processSteps = sf.processSteps.map(s => ({
      num: s.stepNum,
      title: s.stepTitle,
      desc: s.stepDesc,
    }));
  }
  if (sf?.processSubtitle) result.processSubtitle = sf.processSubtitle;
  if (sf?.stats?.length) {
    result.stats = sf.stats.map(s => ({
      value: s.statValue,
      label: s.statLabel,
      description: s.statDescription,
    }));
  }
  result.paragraphSection1 = buildParagraphSection(
    sf?.para1Badge ?? null, sf?.para1Heading ?? null, sf?.para1Body ?? null,
    sf?.para1Image ?? null, sf?.para1ImageAlt ?? null, sf?.para1Bullets ?? null,
  );
  result.paragraphSection2 = buildParagraphSection(
    sf?.para2Badge ?? null, sf?.para2Heading ?? null, sf?.para2Body ?? null,
    sf?.para2Image ?? null, sf?.para2ImageAlt ?? null, sf?.para2Bullets ?? null,
  );
  if (sf?.howItWorksIntro) result.howItWorksIntro = sf.howItWorksIntro;
  if (sf?.howItWorksSteps?.length) {
    result.howItWorksSteps = sf.howItWorksSteps.map(s => ({
      title: s.stepTitle,
      desc: s.stepDesc,
    }));
  }
  if (sf?.ctaImage) result.ctaImage = sf.ctaImage;
  if (sf?.ctaImageAlt) result.ctaImageAlt = sf.ctaImageAlt;

  return result;
}

function transformIndustryNode(node: WpCptNode): IndustryTemplateData {
  const inf = node.industryFields;
  const defaultImg = '/images/stock/service-dumpster-rental.webp';
  return {
    industryName: node.title,
    heroImage: inf?.heroImage || node.featuredImage?.node?.sourceUrl || defaultImg,
    heroDescription: inf?.heroDescription || node.excerpt?.replace(/<[^>]*>/g, '').trim() || `Waste management solutions for the ${node.title} industry.`,
    aboutTitle: inf?.aboutTitle || `${node.title} Waste Solutions`,
    aboutImage: inf?.aboutImage || node.featuredImage?.node?.sourceUrl || defaultImg,
    bulletPoints: inf?.aboutBullets?.map(b => ({ title: b.bulletTitle, description: b.bulletDescription })) || [],
    faqs: inf?.faqs?.length ? inf.faqs : undefined,
    paragraphSection1: buildParagraphSection(
      inf?.para1Badge ?? null, inf?.para1Heading ?? null, inf?.para1Body ?? null,
      inf?.para1Image ?? null, inf?.para1ImageAlt ?? null, inf?.para1Bullets ?? null,
    ),
    paragraphSection2: buildParagraphSection(
      inf?.para2Badge ?? null, inf?.para2Heading ?? null, inf?.para2Body ?? null,
      inf?.para2Image ?? null, inf?.para2ImageAlt ?? null, inf?.para2Bullets ?? null,
    ),
    paragraphSection3: buildParagraphSection(
      inf?.para3Badge ?? null, inf?.para3Heading ?? null, inf?.para3Body ?? null,
      inf?.para3Image ?? null, inf?.para3ImageAlt ?? null, inf?.para3Bullets ?? null,
    ),
    seoMetadata: transformSeoData(node.seo),
  };
}

export const fetchServiceWithAcf = cache(async (slug: string): Promise<ServiceTemplateData | null> => {
  const client = getWpClient();
  try {
    const response = await client.request<{ service: WpCptNode | null }>(
      GET_SERVICE_BY_SLUG_QUERY,
      { slug }
    );
    if (!response.service) return null;
    return transformServiceNode(response.service);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    if (msg.includes('Cannot query field') || msg.includes('not found')) {
      console.warn(`[WP] Service "${slug}" not found:`, msg);
      return null;
    }
    console.error(`[WP] Failed to fetch service with ACF "${slug}":`, error);
    throw error;
  }
});

export const fetchIndustryWithAcf = cache(async (slug: string): Promise<IndustryTemplateData | null> => {
  const client = getWpClient();
  try {
    const response = await client.request<{ industry: WpCptNode | null }>(
      GET_INDUSTRY_BY_SLUG_QUERY,
      { slug }
    );
    if (!response.industry) return null;
    return transformIndustryNode(response.industry);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    if (msg.includes('Cannot query field') || msg.includes('not found')) {
      console.warn(`[WP] Industry "${slug}" not found:`, msg);
      return null;
    }
    console.error(`[WP] Failed to fetch industry with ACF "${slug}":`, error);
    throw error;
  }
});

export async function fetchAllTestimonials(): Promise<TestimonialData[]> {
  const client = getWpClient();
  try {
    const response = await client.request<{ testimonials: { nodes: WpTestimonialNode[] } }>(
      GET_ALL_TESTIMONIALS_QUERY
    );
    return response.testimonials.nodes
      .filter(n => n.testimonialFields)
      .map(n => ({
        quote: n.testimonialFields!.quote,
        author: n.testimonialFields!.authorName,
        role: n.testimonialFields!.authorRole || '',
        company: n.testimonialFields!.company || '',
        img: n.testimonialFields!.authorImage || '',
      }));
  } catch (error) {
    console.error('[WP] Failed to fetch testimonials:', error);
    return [];
  }
}

export async function fetchAllCaseStudies(): Promise<CaseStudyData[]> {
  const client = getWpClient();
  try {
    const response = await client.request<{ caseStudies: { nodes: WpCaseStudyNode[] } }>(
      GET_ALL_CASE_STUDIES_QUERY
    );
    return response.caseStudies.nodes
      .filter(n => n.caseStudyFields)
      .sort((a, b) => {
        const orderA = parseInt(a.caseStudyFields?.displayOrder || '99', 10);
        const orderB = parseInt(b.caseStudyFields?.displayOrder || '99', 10);
        return orderA - orderB;
      })
      .map(n => {
        const cf = n.caseStudyFields!;
        return {
          title: n.title,
          subtitle: cf.subtitle || '',
          tag: cf.tag || '',
          description: cf.description || '',
          mainImage: cf.mainImage || '',
          mainImageAlt: cf.mainImageAlt || '',
          thumbImages: cf.thumbImages?.map(t => ({ src: t.thumbImage, alt: t.thumbAlt })) || [],
          stats: cf.stats?.map(s => ({ value: s.statValue, label: s.statLabel })) || [],
        };
      });
  } catch (error) {
    console.error('[WP] Failed to fetch case studies:', error);
    return [];
  }
}

export async function fetchAllFaqs(): Promise<FaqCategoryData[]> {
  const client = getWpClient();
  try {
    const response = await client.request<{ faqs: { nodes: WpFaqNode[] } }>(
      GET_ALL_FAQS_QUERY
    );
    const categoryMap = new Map<string, { label: string; description?: string; faqs: (FaqData & { order: number })[] }>();
    for (const node of response.faqs.nodes) {
      if (!node.faqFields || !node.title.trim() || !node.faqFields.answer.trim()) continue;
      const cats = node.faqCategories?.nodes || [];
      const catSlug = cats[0]?.slug || 'general';
      const catName = cats[0]?.name || 'General';
      const catDesc = cats[0]?.description || undefined;
      if (!categoryMap.has(catSlug)) {
        categoryMap.set(catSlug, { label: catName, description: catDesc, faqs: [] });
      }
      categoryMap.get(catSlug)!.faqs.push({
        question: node.title,
        answer: node.faqFields.answer,
        order: parseInt(node.faqFields.displayOrder || '99', 10),
      });
    }
    return Array.from(categoryMap.entries()).map(([id, data]) => ({
      id,
      label: data.label,
      description: data.description,
      faqs: data.faqs
        .sort((a, b) => a.order - b.order)
        .map(({ question, answer }) => ({ question, answer })),
    }));
  } catch (error) {
    console.error('[WP] Failed to fetch FAQs:', error);
    return [];
  }
}

export async function fetchAllPartnerLogos(): Promise<PartnerLogoData[]> {
  const client = getWpClient();
  try {
    const response = await client.request<{ partnerLogos: { nodes: WpPartnerLogoNode[] } }>(
      GET_ALL_PARTNER_LOGOS_QUERY
    );
    return response.partnerLogos.nodes
      .filter(n => n.partnerLogoFields?.logoImage)
      .sort((a, b) => {
        const orderA = parseInt(a.partnerLogoFields?.displayOrder || '99', 10);
        const orderB = parseInt(b.partnerLogoFields?.displayOrder || '99', 10);
        return orderA - orderB;
      })
      .map(n => ({
        src: n.partnerLogoFields!.logoImage!,
        alt: n.partnerLogoFields!.logoAlt || n.title,
      }));
  } catch (error) {
    console.error('[WP] Failed to fetch partner logos:', error);
    return [];
  }
}

// ═══════════════════════════════════════════════════════
// PAGE TEMPLATE ACF DATA — Interfaces
// ═══════════════════════════════════════════════════════

export interface SimpleNumber { value: string; suffix: string; label: string }
export interface ServiceCategorySubItem { label: string; description: string }
export interface ServiceCategory { title: string; description: string; link: string; subItems: ServiceCategorySubItem[] | null }
export interface WhyUsFeature { title: string; content: string; iconName: string }
export interface InlineFaqItem { question: string; answer: string }
export interface ProcessStep { number: string; title: string; description: string }
export interface StatCard { title: string; value: string; description: string }
export interface ReasonFeature { iconName: string; title: string; description: string }
export interface AssociationLogo { logo: string; altText: string }
export interface CoreValue { title: string; description: string }
export interface BenefitCard { iconName: string; title: string; description: string }
export interface HowStep { number: string; title: string; description: string }
export interface StatBullet { text: string }
export interface StatNumber { value: string; label: string }
export interface HoursLine { line: string }
export interface InterestOption { value: string; label: string }
export interface ExpectationItem { text: string }
export interface NextStepItem { text: string }

export interface HomepageTemplateData {
  heroTagline?: string;
  heroHeading?: string;
  heroSubheading?: string;
  heroVideo?: string;
  heroCtaLabel?: string;
  heroCtaLink?: string;
  heroSecondaryLabel?: string;
  heroSecondaryLink?: string;
  simpleNumbers?: SimpleNumber[];
  servicesTagline?: string;
  servicesHeading?: string;
  servicesSubtitle?: string;
  servicesCategories?: ServiceCategory[];
  whyUsHeading?: string;
  whyUsImage?: string;
  whyUsImageAlt?: string;
  whyUsFeatures?: WhyUsFeature[];
  whyUsCtaLabel?: string;
  whyUsCtaLink?: string;
  whyUsSecondaryLabel?: string;
  whyUsSecondaryLink?: string;
  faqTagline?: string;
  faqHeading?: string;
  faqSubtitle?: string;
  faqItems?: InlineFaqItem[];
  faqCtaText?: string;
  faqCtaLabel?: string;
  faqCtaLink?: string;
  seoMetadata?: SeoMetadata;
}

export interface AboutTemplateData {
  storyTagline?: string;
  storyHeading?: string;
  storyBody?: string;
  storyImage?: string;
  storyImageAlt?: string;
  coreHeading?: string;
  coreValues?: CoreValue[];
  coreImage?: string;
  coreImageAlt?: string;
  coreCtaLabel?: string;
  coreCtaLink?: string;
  coreSecondaryLabel?: string;
  coreSecondaryLink?: string;
  associationsHeading?: string;
  associationsLogos?: AssociationLogo[];
  communityHeading?: string;
  communityBody?: string;
  communityImage?: string;
  communityImageAlt?: string;
  communityCtaLabel?: string;
  communityCtaLink?: string;
  communitySecondaryLabel?: string;
  communitySecondaryLink?: string;
  seoMetadata?: SeoMetadata;
}

export interface HeroPageTemplateData {
  heroHeading?: string;
  heroSubheading?: string;
  heroImage?: string;
  heroCtaLabel?: string;
  heroCtaLink?: string;
  heroPhoneLabel?: string;
  heroPhoneLink?: string;
  seoMetadata?: SeoMetadata;
}

export interface LocationsPageTemplateData extends HeroPageTemplateData {
  areasHeading?: string;
  areasSubtitle?: string;
}

export interface CwProcessStep { number?: string; title?: string; description?: string; }
export interface CwThumb { image?: string; alt?: string; }
export interface CwStat { value?: string; label?: string; }
export interface CwFaq { question?: string; answer?: string; }

export interface CommercialWasteTemplateData extends HeroPageTemplateData {
  processTagline?: string;
  processHeading?: string;
  processSubtitle?: string;
  processSteps?: CwProcessStep[];
  zipTagline?: string;
  zipHeading?: string;
  zipHeadingHighlight?: string;
  zipSubtitle?: string;
  zipPlaceholder?: string;
  zipButton?: string;
  caseStudyTag?: string;
  caseStudyHeading?: string;
  caseStudySubheading?: string;
  caseStudyBody?: string;
  caseStudyMainImage?: string;
  caseStudyThumbs?: CwThumb[];
  caseStudyStats?: CwStat[];
  caseStudyCtaLabel?: string;
  caseStudyCtaLink?: string;
  faqTagline?: string;
  faqHeading?: string;
  faqSubtitle?: string;
  faqs?: CwFaq[];
  faqCtaText?: string;
  faqCtaLabel?: string;
  faqCtaLink?: string;
}

export interface JoinNetworkTemplateData {
  heroHeading?: string;
  heroSubheading?: string;
  heroImage?: string;
  heroCtaLabel?: string;
  heroPhoneLabel?: string;
  heroPhoneLink?: string;
  logosHeadline?: string;
  benefitsTagline?: string;
  benefitsHeading?: string;
  benefitsSubtitle?: string;
  benefitsCards?: BenefitCard[];
  howHeading?: string;
  howSubtitle?: string;
  howSteps?: HowStep[];
  statsHeading?: string;
  statsBullets?: StatBullet[];
  statsNumbers?: StatNumber[];
  emailTagline?: string;
  emailHeading?: string;
  emailSubtitle?: string;
  emailPlaceholder?: string;
  emailSubmitLabel?: string;
  emailDisclaimer?: string;
  emailSuccessHeading?: string;
  emailSuccessMessage?: string;
  seoMetadata?: SeoMetadata;
}

export interface FaqPageTemplateData {
  heroTagline?: string;
  heroHeading?: string;
  heroHeadingHighlight?: string;
  heroSubtitle?: string;
  heroImage?: string;
  ctaText?: string;
  ctaLabel?: string;
  ctaLink?: string;
  seoMetadata?: SeoMetadata;
}

export interface ContactFormTemplateData {
  pageHeading?: string;
  emergencyText?: string;
  emergencyPhone?: string;
  emergencyPhoneLink?: string;
  vendorText?: string;
  vendorLinkText?: string;
  vendorLinkUrl?: string;
  cardHeading?: string;
  phone?: string;
  phoneLink?: string;
  email?: string;
  emailLink?: string;
  hours?: HoursLine[];
  formHeading?: string;
  formSubtitle?: string;
  interestOptions?: InterestOption[];
  messageLabel?: string;
  submitLabel?: string;
  privacyText?: string;
  privacyLinkText?: string;
  privacyLinkUrl?: string;
  seoMetadata?: SeoMetadata;
}

export interface BookCallTemplateData {
  heading?: string;
  expectations?: ExpectationItem[];
  description?: string;
  calendarEmbed?: string;
  calendarFallbackHeading?: string;
  calendarFallbackText?: string;
  skipText?: string;
  continueLabel?: string;
  continueLink?: string;
  seoMetadata?: SeoMetadata;
}

export interface ThankYouTemplateData {
  heading?: string;
  subtitle?: string;
  stepsHeading?: string;
  nextSteps?: NextStepItem[];
  ctaLabel?: string;
  ctaLink?: string;
  secondaryLabel?: string;
  secondaryLink?: string;
  seoMetadata?: SeoMetadata;
}

export interface LegalPageTemplateData {
  heading?: string;
  bodyContent?: string;
  seoMetadata?: SeoMetadata;
}

export interface GlobalSectionsData {
  process?: {
    tagline?: string;
    heading?: string;
    subtitle?: string;
    steps?: ProcessStep[];
  };
  stats?: {
    tagline?: string;
    heading?: string;
    subtitle?: string;
    ctaLabel?: string;
    ctaLink?: string;
    phoneLabel?: string;
    phoneLink?: string;
    image?: string;
    imageAlt?: string;
    cards?: StatCard[];
  };
  ctaBanner?: {
    tagline?: string;
    heading?: string;
    subtitle?: string;
    placeholder?: string;
    button?: string;
  };
  reasons?: {
    tagline?: string;
    heading?: string;
    subtitle?: string;
    ctaLabel?: string;
    ctaLink?: string;
    features?: ReasonFeature[];
  };
  finalCta?: {
    heading?: string;
    subtitle?: string;
    label?: string;
    link?: string;
    image?: string;
    imageAlt?: string;
    phone?: string;
    phoneLink?: string;
  };
  location?: {
    heading?: string;
    subtitle?: string;
    address?: string;
    addressLink?: string;
    phoneNote?: string;
    phone?: string;
    phoneLink?: string;
    email?: string;
    emailLink?: string;
  };
  faq?: {
    tagline?: string;
    heading?: string;
    subtitle?: string;
    faqs?: InlineFaqItem[];
    ctaText?: string;
    ctaLabel?: string;
    ctaLink?: string;
  };
  whoHelp?: {
    tagline?: string;
    heading?: string;
    subtitle?: string;
  };
  logoReel?: {
    headline?: string;
  };
  testimonials?: {
    tagline?: string;
  };
}

// ═══════════════════════════════════════════════════════
// PAGE TEMPLATE ACF DATA — GraphQL Queries
// ═══════════════════════════════════════════════════════

const GET_PAGE_TEMPLATE_ACF_QUERY = gql`
  ${SEO_FRAGMENT}
  query GetPageTemplateAcf($slug: ID!) {
    page(id: $slug, idType: URI) {
      databaseId
      slug
      title
      seo { ...SeoFields }
      homepageFields {
        heroTagline
        heroHeading
        heroSubheading
        heroVideo
        heroCtaLabel
        heroCtaLink
        heroSecondaryLabel
        heroSecondaryLink
        simpleNumbers { value suffix label }
        servicesTagline
        servicesHeading
        servicesSubtitle
        servicesCategories {
          title
          description
          link
          subItems { label description }
        }
        whyUsHeading
        whyUsImage
        whyUsImageAlt
        whyUsFeatures { title content iconName }
        whyUsCtaLabel
        whyUsCtaLink
        whyUsSecondaryLabel
        whyUsSecondaryLink
        faqTagline
        faqHeading
        faqSubtitle
        faqItems { question answer }
        faqCtaText
        faqCtaLabel
        faqCtaLink
      }
      aboutFields {
        storyTagline
        storyHeading
        storyBody
        storyImage
        storyImageAlt
        coreHeading
        coreValues { title description }
        coreImage
        coreImageAlt
        coreCtaLabel
        coreCtaLink
        coreSecondaryLabel
        coreSecondaryLink
        associationsHeading
        associationsLogos { logo altText }
        communityHeading
        communityBody
        communityImage
        communityImageAlt
        communityCtaLabel
        communityCtaLink
        communitySecondaryLabel
        communitySecondaryLink
      }
      commercialWasteFields {
        heroHeading
        heroSubheading
        heroImage
        heroCtaLabel
        heroCtaLink
        heroPhoneLabel
        heroPhoneLink
      }
      commercialWasteBodyFields {
        processTagline
        processHeading
        processSubtitle
        processSteps { number title description }
        zipTagline
        zipHeading
        zipHeadingHighlight
        zipSubtitle
        zipPlaceholder
        zipButton
        caseStudyTag
        caseStudyHeading
        caseStudySubheading
        caseStudyBody
        caseStudyMainImage
        caseStudyThumbs { image alt }
        caseStudyStats { value label }
        caseStudyCtaLabel
        caseStudyCtaLink
        faqTagline
        faqHeading
        faqSubtitle
        faqs { question answer }
        faqCtaText
        faqCtaLabel
        faqCtaLink
      }
      whoWeServeFields {
        heroHeading
        heroSubheading
        heroImage
        heroCtaLabel
        heroCtaLink
        heroPhoneLabel
        heroPhoneLink
      }
      ourProcessFields {
        heroHeading
        heroSubheading
        heroImage
        heroCtaLabel
        heroCtaLink
        heroPhoneLabel
        heroPhoneLink
      }
      locationsFields {
        heroHeading
        heroSubheading
        heroImage
        heroCtaLabel
        heroCtaLink
        heroPhoneLabel
        heroPhoneLink
        areasHeading
        areasSubtitle
      }
      joinNetworkFields {
        heroHeading
        heroSubheading
        heroImage
        heroCtaLabel
        heroPhoneLabel
        heroPhoneLink
        logosHeadline
        benefitsTagline
        benefitsHeading
        benefitsSubtitle
        benefitsCards { iconName title description }
        howHeading
        howSubtitle
        howSteps { number title description }
        statsHeading
        statsBullets { text }
        statsNumbers { value label }
        emailTagline
        emailHeading
        emailSubtitle
        emailPlaceholder
        emailSubmitLabel
        emailDisclaimer
        emailSuccessHeading
        emailSuccessMessage
      }
      faqPageFields {
        heroTagline
        heroHeading
        heroHeadingHighlight
        heroSubtitle
        heroImage
        ctaText
        ctaLabel
        ctaLink
      }
      contactFields {
        pageHeading
        emergencyText
        emergencyPhone
        emergencyPhoneLink
        vendorText
        vendorLinkText
        vendorLinkUrl
        cardHeading
        phone
        phoneLink
        email
        emailLink
        hours { line }
        formHeading
        formSubtitle
        interestOptions { value label }
        submitLabel
        privacyText
        privacyLinkText
        privacyLinkUrl
      }
      requestServiceFields {
        pageHeading
        emergencyText
        emergencyPhone
        emergencyPhoneLink
        vendorText
        vendorLinkText
        vendorLinkUrl
        cardHeading
        phone
        phoneLink
        email
        emailLink
        hours { line }
        formHeading
        formSubtitle
        interestOptions { value label }
        messageLabel
        submitLabel
        privacyText
        privacyLinkText
        privacyLinkUrl
      }
      bookCallFields {
        heading
        expectations { text }
        description
        calendarEmbed
        calendarFallbackHeading
        calendarFallbackText
        skipText
        continueLabel
        continueLink
      }
      thankYouFields {
        heading
        subtitle
        stepsHeading
        nextSteps { text }
        ctaLabel
        ctaLink
        secondaryLabel
        secondaryLink
      }
      privacyFields {
        heading
        bodyContent
      }
      termsFields {
        heading
        bodyContent
      }
    }
  }
`;

const GET_GLOBAL_SECTIONS_QUERY = gql`
  query GetGlobalSections {
    trGlobalSections {
      gsProcess {
        processTagline
        processHeading
        processSubtitle
        processSteps { number title description }
      }
      gsStats {
        statsTagline
        statsHeading
        statsSubtitle
        statsCtaLabel
        statsCtaLink
        statsPhoneLabel
        statsPhoneLink
        statsImage
        statsImageAlt
        statsCards { title value description }
      }
      gsCtaBanner {
        ctaBannerTagline
        ctaBannerHeading
        ctaBannerSubtitle
        ctaBannerPlaceholder
        ctaBannerButton
      }
      gsReasons {
        reasonsTagline
        reasonsHeading
        reasonsSubtitle
        reasonsCtaLabel
        reasonsCtaLink
        reasonsFeatures { iconName title description }
      }
      gsFinalCta {
        finalCtaHeading
        finalCtaSubtitle
        finalCtaLabel
        finalCtaLink
        finalCtaImage
        finalCtaImageAlt
        finalCtaPhone
        finalCtaPhoneLink
      }
      gsLocation {
        locationHeading
        locationSubtitle
        locationAddress
        locationAddressLink
        locationPhoneNote
        locationPhone
        locationPhoneLink
        locationEmail
        locationEmailLink
        locationHqImage
        locationHqImageAlt
      }
      gsFaq {
        faqSectionTagline
        faqSectionHeading
        faqSectionSubtitle
        faqItems { question answer }
        faqSectionCtaText
        faqSectionCtaLabel
        faqSectionCtaLink
      }
      gsWhoHelp {
        whoHelpTagline
        whoHelpHeading
        whoHelpSubtitle
      }
      gsLogoReel {
        logoReelHeadline
      }
      gsTestimonials {
        testimonialsTagline
      }
    }
  }
`;

// ═══════════════════════════════════════════════════════
// PAGE TEMPLATE ACF DATA — Fetcher Functions
// ═══════════════════════════════════════════════════════

interface WpPageAcfResponse {
  page: {
    databaseId: number;
    slug: string;
    title: string;
    seo: WpSeo | null;
    homepageFields: Record<string, unknown> | null;
    aboutFields: Record<string, unknown> | null;
    commercialWasteFields: Record<string, unknown> | null;
    commercialWasteBodyFields: Record<string, unknown> | null;
    whoWeServeFields: Record<string, unknown> | null;
    ourProcessFields: Record<string, unknown> | null;
    locationsFields: Record<string, unknown> | null;
    joinNetworkFields: Record<string, unknown> | null;
    faqPageFields: Record<string, unknown> | null;
    contactFields: Record<string, unknown> | null;
    requestServiceFields: Record<string, unknown> | null;
    bookCallFields: Record<string, unknown> | null;
    thankYouFields: Record<string, unknown> | null;
    privacyFields: Record<string, unknown> | null;
    termsFields: Record<string, unknown> | null;
  } | null;
}

// ─────────────────────────────────────────────────────────────
// Page-template → current WP slug map
// Each of the 14 page-template pages is identified in WP by the
// `headlessTemplate` field (registered in scripts/register-page-templates-snippet.php).
// We look up its current slug here so editors can rename the WP slug
// freely without breaking the ACF fetch (and middleware can redirect
// the canonical front-end route to the new slug).
// ─────────────────────────────────────────────────────────────
const GET_PAGE_TEMPLATE_SLUGS_QUERY = gql`
  query GetPageTemplateSlugs {
    pages(first: 100, where: { status: PUBLISH }) {
      nodes { slug headlessTemplate }
    }
  }
`;

export const fetchPageTemplateSlugMap = cache(async (): Promise<Record<string, string>> => {
  const client = getWpClient();
  try {
    const data = await client.request<{ pages: { nodes: Array<{ slug: string; headlessTemplate: string | null }> } }>(
      GET_PAGE_TEMPLATE_SLUGS_QUERY
    );
    const map: Record<string, string> = {};
    for (const node of data?.pages?.nodes || []) {
      if (node?.headlessTemplate && node?.slug) {
        map[node.headlessTemplate] = node.slug;
      }
    }
    return map;
  } catch (error) {
    console.error('[WP] Failed to fetch page template slug map:', error);
    return {};
  }
});

async function resolveTemplateSlug(wpTemplate: string, fallback: string): Promise<string> {
  const map = await fetchPageTemplateSlugMap();
  return map[wpTemplate] || fallback;
}

/**
 * Fetch the page-template ACF payload without serializing on the slug-map
 * lookup. We kick off the ACF query against the fallback slug in parallel with
 * the slug-map fetch; if WP confirms the slug hasn't been renamed (the common
 * case) we return the already-in-flight result with no second round-trip. If
 * the editor has renamed the slug, we refetch with the resolved slug.
 *
 * `cache()` on both the slug map and `getWpClient()` means concurrent callers
 * within one request share state — no duplicate work.
 */
async function fetchPageTemplateAcfData(
  wpTemplate: string,
  fallbackSlug: string,
): Promise<WpPageAcfResponse> {
  const client = getWpClient();
  const slugMapP = fetchPageTemplateSlugMap();
  const fallbackReqP = client.request<WpPageAcfResponse>(
    GET_PAGE_TEMPLATE_ACF_QUERY,
    { slug: `/${fallbackSlug}/` },
  );
  // Avoid an unhandled-rejection warning if we end up abandoning this promise
  // because the slug was renamed.
  fallbackReqP.catch(() => {});
  const slugMap = await slugMapP;
  const actualSlug = slugMap[wpTemplate] || fallbackSlug;
  if (actualSlug === fallbackSlug) return fallbackReqP;
  return client.request<WpPageAcfResponse>(
    GET_PAGE_TEMPLATE_ACF_QUERY,
    { slug: `/${actualSlug}/` },
  );
}

// Lightweight SEO-only fetch for page templates. Use this when the matching
// ACF fetcher may return null (because its ACF group is empty in WP) but we
// still want the Yoast SEO schema for the page. Resolves slug via the same
// template-slug map so editor renames propagate.
// Look up by slug-name via the pages list rather than `page(id, URI)`, since URIs
// like /services/ and /industries/ collide with CPT archive URIs and return null
// from the singular `page` lookup. The `where: {name: ...}` filter resolves the
// page entity directly by its post_name regardless of permalink collisions.
const GET_PAGE_SEO_QUERY = gql`
  ${SEO_FRAGMENT}
  query GetPageSeoBySlug($slug: String!) {
    pages(first: 1, where: { name: $slug }) {
      nodes { seo { ...SeoFields } }
    }
  }
`;

export const fetchPageTemplateSeo = cache(
  async (wpTemplate: string, fallbackSlug: string): Promise<SeoMetadata | undefined> => {
    const client = getWpClient();
    try {
      const slug = await resolveTemplateSlug(wpTemplate, fallbackSlug);
      const { pages } = await client.request<{ pages: { nodes: Array<{ seo: WpSeo | null }> } }>(
        GET_PAGE_SEO_QUERY,
        { slug },
      );
      return transformSeoData(pages?.nodes?.[0]?.seo || null);
    } catch (error) {
      console.error(`[WP] Failed to fetch SEO for ${wpTemplate}:`, error);
      return undefined;
    }
  },
);

function hasData(obj: Record<string, unknown> | null): boolean {
  if (!obj) return false;
  return Object.values(obj).some(v => {
    if (v === null || v === undefined || v === '') return false;
    if (Array.isArray(v) && v.length === 0) return false;
    return true;
  });
}

function nonEmpty<T>(val: T | null | undefined): T | undefined {
  if (val === null || val === undefined || val === '') return undefined;
  if (Array.isArray(val) && val.length === 0) return undefined;
  return val;
}

export const fetchHomepageAcf = cache(async (): Promise<HomepageTemplateData | null> => {
  try {
    const { page } = await fetchPageTemplateAcfData('template-homepage', 'home');
    if (!page?.homepageFields || !hasData(page.homepageFields)) return null;
    const f = page.homepageFields as Record<string, any>;
    return {
      heroTagline: f.heroTagline || undefined,
      heroHeading: f.heroHeading || undefined,
      heroSubheading: f.heroSubheading || undefined,
      heroVideo: f.heroVideo || undefined,
      heroCtaLabel: f.heroCtaLabel || undefined,
      heroCtaLink: f.heroCtaLink || undefined,
      heroSecondaryLabel: f.heroSecondaryLabel || undefined,
      heroSecondaryLink: f.heroSecondaryLink || undefined,
      simpleNumbers: nonEmpty(f.simpleNumbers),
      servicesTagline: f.servicesTagline || undefined,
      servicesHeading: f.servicesHeading || undefined,
      servicesSubtitle: f.servicesSubtitle || undefined,
      servicesCategories: nonEmpty(f.servicesCategories),
      whyUsHeading: f.whyUsHeading || undefined,
      whyUsImage: f.whyUsImage || undefined,
      whyUsImageAlt: f.whyUsImageAlt || undefined,
      whyUsFeatures: nonEmpty(f.whyUsFeatures),
      whyUsCtaLabel: f.whyUsCtaLabel || undefined,
      whyUsCtaLink: f.whyUsCtaLink || undefined,
      whyUsSecondaryLabel: f.whyUsSecondaryLabel || undefined,
      whyUsSecondaryLink: f.whyUsSecondaryLink || undefined,
      faqTagline: f.faqTagline || undefined,
      faqHeading: f.faqHeading || undefined,
      faqSubtitle: f.faqSubtitle || undefined,
      faqItems: nonEmpty(f.faqItems),
      faqCtaText: f.faqCtaText || undefined,
      faqCtaLabel: f.faqCtaLabel || undefined,
      faqCtaLink: f.faqCtaLink || undefined,
      seoMetadata: transformSeoData(page.seo),
    };
  } catch (error) {
    console.error('[WP] Failed to fetch homepage ACF:', error);
    return null;
  }
});

export const fetchAboutAcf = cache(async (): Promise<AboutTemplateData | null> => {
  try {
    const { page } = await fetchPageTemplateAcfData('template-about', 'about');
    if (!page?.aboutFields || !hasData(page.aboutFields)) return null;
    const f = page.aboutFields as Record<string, any>;
    return {
      storyTagline: f.storyTagline || undefined,
      storyHeading: f.storyHeading || undefined,
      storyBody: f.storyBody || undefined,
      storyImage: f.storyImage || undefined,
      storyImageAlt: f.storyImageAlt || undefined,
      coreHeading: f.coreHeading || undefined,
      coreValues: nonEmpty(f.coreValues),
      coreImage: f.coreImage || undefined,
      coreImageAlt: f.coreImageAlt || undefined,
      coreCtaLabel: f.coreCtaLabel || undefined,
      coreCtaLink: f.coreCtaLink || undefined,
      coreSecondaryLabel: f.coreSecondaryLabel || undefined,
      coreSecondaryLink: f.coreSecondaryLink || undefined,
      associationsHeading: f.associationsHeading || undefined,
      associationsLogos: nonEmpty(f.associationsLogos),
      communityHeading: f.communityHeading || undefined,
      communityBody: f.communityBody || undefined,
      communityImage: f.communityImage || undefined,
      communityImageAlt: f.communityImageAlt || undefined,
      communityCtaLabel: f.communityCtaLabel || undefined,
      communityCtaLink: f.communityCtaLink || undefined,
      communitySecondaryLabel: f.communitySecondaryLabel || undefined,
      communitySecondaryLink: f.communitySecondaryLink || undefined,
      seoMetadata: transformSeoData(page.seo),
    };
  } catch (error) {
    console.error('[WP] Failed to fetch about ACF:', error);
    return null;
  }
});

async function fetchHeroPageAcf(wpTemplate: string, fallbackSlug: string, fieldName: string): Promise<HeroPageTemplateData | null> {
  try {
    const { page } = await fetchPageTemplateAcfData(wpTemplate, fallbackSlug);
    const fields = (page as any)?.[fieldName];
    if (!fields || !hasData(fields)) return null;
    return {
      heroHeading: fields.heroHeading || undefined,
      heroSubheading: fields.heroSubheading || undefined,
      heroImage: fields.heroImage || undefined,
      heroCtaLabel: fields.heroCtaLabel || undefined,
      heroCtaLink: fields.heroCtaLink || undefined,
      heroPhoneLabel: fields.heroPhoneLabel || undefined,
      heroPhoneLink: fields.heroPhoneLink || undefined,
      seoMetadata: transformSeoData(page?.seo || null),
    };
  } catch (error) {
    console.error(`[WP] Failed to fetch ${wpTemplate} ACF:`, error);
    return null;
  }
}

export const fetchCommercialWasteAcf = cache(async (): Promise<CommercialWasteTemplateData | null> => {
  try {
    const { page } = await fetchPageTemplateAcfData('template-commercial-waste', 'commercial-waste');
    const hero = page?.commercialWasteFields as Record<string, any> | null | undefined;
    const body = page?.commercialWasteBodyFields as Record<string, any> | null | undefined;
    if ((!hero || !hasData(hero)) && (!body || !hasData(body))) return null;
    const h = hero || {};
    const b = body || {};
    return {
      heroHeading: h.heroHeading || undefined,
      heroSubheading: h.heroSubheading || undefined,
      heroImage: h.heroImage || undefined,
      heroCtaLabel: h.heroCtaLabel || undefined,
      heroCtaLink: h.heroCtaLink || undefined,
      heroPhoneLabel: h.heroPhoneLabel || undefined,
      heroPhoneLink: h.heroPhoneLink || undefined,
      processTagline: b.processTagline || undefined,
      processHeading: b.processHeading || undefined,
      processSubtitle: b.processSubtitle || undefined,
      processSteps: nonEmpty(b.processSteps),
      zipTagline: b.zipTagline || undefined,
      zipHeading: b.zipHeading || undefined,
      zipHeadingHighlight: b.zipHeadingHighlight || undefined,
      zipSubtitle: b.zipSubtitle || undefined,
      zipPlaceholder: b.zipPlaceholder || undefined,
      zipButton: b.zipButton || undefined,
      caseStudyTag: b.caseStudyTag || undefined,
      caseStudyHeading: b.caseStudyHeading || undefined,
      caseStudySubheading: b.caseStudySubheading || undefined,
      caseStudyBody: b.caseStudyBody || undefined,
      caseStudyMainImage: b.caseStudyMainImage || undefined,
      caseStudyThumbs: nonEmpty(b.caseStudyThumbs),
      caseStudyStats: nonEmpty(b.caseStudyStats),
      caseStudyCtaLabel: b.caseStudyCtaLabel || undefined,
      caseStudyCtaLink: b.caseStudyCtaLink || undefined,
      faqTagline: b.faqTagline || undefined,
      faqHeading: b.faqHeading || undefined,
      faqSubtitle: b.faqSubtitle || undefined,
      faqs: nonEmpty(b.faqs),
      faqCtaText: b.faqCtaText || undefined,
      faqCtaLabel: b.faqCtaLabel || undefined,
      faqCtaLink: b.faqCtaLink || undefined,
      seoMetadata: transformSeoData(page?.seo || null),
    };
  } catch (error) {
    console.error('[WP] Failed to fetch commercial waste ACF:', error);
    return null;
  }
});

export const fetchWhoWeServeAcf = cache(async (): Promise<HeroPageTemplateData | null> => {
  return fetchHeroPageAcf('template-who-we-serve', 'who-we-serve', 'whoWeServeFields');
});

export const fetchOurProcessAcf = cache(async (): Promise<HeroPageTemplateData | null> => {
  return fetchHeroPageAcf('template-our-process', 'our-process', 'ourProcessFields');
});

export const fetchLocationsPageAcf = cache(async (): Promise<LocationsPageTemplateData | null> => {
  try {
    const { page } = await fetchPageTemplateAcfData('template-locations', 'locations');
    if (!page?.locationsFields || !hasData(page.locationsFields)) return null;
    const f = page.locationsFields as Record<string, any>;
    return {
      heroHeading: f.heroHeading || undefined,
      heroSubheading: f.heroSubheading || undefined,
      heroImage: f.heroImage || undefined,
      heroCtaLabel: f.heroCtaLabel || undefined,
      heroCtaLink: f.heroCtaLink || undefined,
      heroPhoneLabel: f.heroPhoneLabel || undefined,
      heroPhoneLink: f.heroPhoneLink || undefined,
      areasHeading: f.areasHeading || undefined,
      areasSubtitle: f.areasSubtitle || undefined,
      seoMetadata: transformSeoData(page.seo),
    };
  } catch (error) {
    console.error('[WP] Failed to fetch locations page ACF:', error);
    return null;
  }
});

export const fetchJoinNetworkAcf = cache(async (): Promise<JoinNetworkTemplateData | null> => {
  try {
    const { page } = await fetchPageTemplateAcfData('template-join-our-network', 'join-our-network');
    if (!page?.joinNetworkFields || !hasData(page.joinNetworkFields)) return null;
    const f = page.joinNetworkFields as Record<string, any>;
    return {
      heroHeading: f.heroHeading || undefined,
      heroSubheading: f.heroSubheading || undefined,
      heroImage: f.heroImage || undefined,
      heroCtaLabel: f.heroCtaLabel || undefined,
      heroPhoneLabel: f.heroPhoneLabel || undefined,
      heroPhoneLink: f.heroPhoneLink || undefined,
      logosHeadline: f.logosHeadline || undefined,
      benefitsTagline: f.benefitsTagline || undefined,
      benefitsHeading: f.benefitsHeading || undefined,
      benefitsSubtitle: f.benefitsSubtitle || undefined,
      benefitsCards: nonEmpty(f.benefitsCards),
      howHeading: f.howHeading || undefined,
      howSubtitle: f.howSubtitle || undefined,
      howSteps: nonEmpty(f.howSteps),
      statsHeading: f.statsHeading || undefined,
      statsBullets: nonEmpty(f.statsBullets),
      statsNumbers: nonEmpty(f.statsNumbers),
      emailTagline: f.emailTagline || undefined,
      emailHeading: f.emailHeading || undefined,
      emailSubtitle: f.emailSubtitle || undefined,
      emailPlaceholder: f.emailPlaceholder || undefined,
      emailSubmitLabel: f.emailSubmitLabel || undefined,
      emailDisclaimer: f.emailDisclaimer || undefined,
      emailSuccessHeading: f.emailSuccessHeading || undefined,
      emailSuccessMessage: f.emailSuccessMessage || undefined,
      seoMetadata: transformSeoData(page.seo),
    };
  } catch (error) {
    console.error('[WP] Failed to fetch join network ACF:', error);
    return null;
  }
});

export const fetchFaqPageAcf = cache(async (): Promise<FaqPageTemplateData | null> => {
  try {
    const { page } = await fetchPageTemplateAcfData('template-faq', 'faq');
    if (!page?.faqPageFields || !hasData(page.faqPageFields)) return null;
    const f = page.faqPageFields as Record<string, any>;
    return {
      heroTagline: f.heroTagline || undefined,
      heroHeading: f.heroHeading || undefined,
      heroHeadingHighlight: f.heroHeadingHighlight || undefined,
      heroSubtitle: f.heroSubtitle || undefined,
      heroImage: f.heroImage || undefined,
      ctaText: f.ctaText || undefined,
      ctaLabel: f.ctaLabel || undefined,
      ctaLink: f.ctaLink || undefined,
      seoMetadata: transformSeoData(page.seo),
    };
  } catch (error) {
    console.error('[WP] Failed to fetch FAQ page ACF:', error);
    return null;
  }
});

async function fetchContactFormAcf(wpTemplate: string, fallbackSlug: string, fieldName: string): Promise<ContactFormTemplateData | null> {
  try {
    const { page } = await fetchPageTemplateAcfData(wpTemplate, fallbackSlug);
    const fields = (page as any)?.[fieldName];
    if (!fields || !hasData(fields)) return null;
    return {
      pageHeading: fields.pageHeading || undefined,
      emergencyText: fields.emergencyText || undefined,
      emergencyPhone: fields.emergencyPhone || undefined,
      emergencyPhoneLink: fields.emergencyPhoneLink || undefined,
      vendorText: fields.vendorText || undefined,
      vendorLinkText: fields.vendorLinkText || undefined,
      vendorLinkUrl: fields.vendorLinkUrl || undefined,
      cardHeading: fields.cardHeading || undefined,
      phone: fields.phone || undefined,
      phoneLink: fields.phoneLink || undefined,
      email: fields.email || undefined,
      emailLink: fields.emailLink || undefined,
      hours: nonEmpty(fields.hours),
      formHeading: fields.formHeading || undefined,
      formSubtitle: fields.formSubtitle || undefined,
      interestOptions: nonEmpty(fields.interestOptions),
      messageLabel: fields.messageLabel || undefined,
      submitLabel: fields.submitLabel || undefined,
      privacyText: fields.privacyText || undefined,
      privacyLinkText: fields.privacyLinkText || undefined,
      privacyLinkUrl: fields.privacyLinkUrl || undefined,
      seoMetadata: transformSeoData(page?.seo || null),
    };
  } catch (error) {
    console.error(`[WP] Failed to fetch ${wpTemplate} ACF:`, error);
    return null;
  }
}

export const fetchContactAcf = cache(async (): Promise<ContactFormTemplateData | null> => {
  return fetchContactFormAcf('template-contact', 'contact', 'contactFields');
});

export const fetchRequestServiceAcf = cache(async (): Promise<ContactFormTemplateData | null> => {
  return fetchContactFormAcf('template-request-a-service', 'request-a-service', 'requestServiceFields');
});

export const fetchBookCallAcf = cache(async (): Promise<BookCallTemplateData | null> => {
  try {
    const { page } = await fetchPageTemplateAcfData('template-book-a-call', 'book-a-call');
    if (!page?.bookCallFields || !hasData(page.bookCallFields)) return null;
    const f = page.bookCallFields as Record<string, any>;
    return {
      heading: f.heading || undefined,
      expectations: nonEmpty(f.expectations),
      description: f.description || undefined,
      calendarEmbed: f.calendarEmbed || undefined,
      calendarFallbackHeading: f.calendarFallbackHeading || undefined,
      calendarFallbackText: f.calendarFallbackText || undefined,
      skipText: f.skipText || undefined,
      continueLabel: f.continueLabel || undefined,
      continueLink: f.continueLink || undefined,
      seoMetadata: transformSeoData(page.seo),
    };
  } catch (error) {
    console.error('[WP] Failed to fetch book-a-call ACF:', error);
    return null;
  }
});

export const fetchThankYouAcf = cache(async (): Promise<ThankYouTemplateData | null> => {
  try {
    const { page } = await fetchPageTemplateAcfData('template-thank-you', 'thank-you');
    if (!page?.thankYouFields || !hasData(page.thankYouFields)) return null;
    const f = page.thankYouFields as Record<string, any>;
    return {
      heading: f.heading || undefined,
      subtitle: f.subtitle || undefined,
      stepsHeading: f.stepsHeading || undefined,
      nextSteps: nonEmpty(f.nextSteps),
      ctaLabel: f.ctaLabel || undefined,
      ctaLink: f.ctaLink || undefined,
      secondaryLabel: f.secondaryLabel || undefined,
      secondaryLink: f.secondaryLink || undefined,
      seoMetadata: transformSeoData(page.seo),
    };
  } catch (error) {
    console.error('[WP] Failed to fetch thank-you ACF:', error);
    return null;
  }
});

async function fetchLegalPageAcf(wpTemplate: string, fallbackSlug: string, fieldName: string): Promise<LegalPageTemplateData | null> {
  try {
    const { page } = await fetchPageTemplateAcfData(wpTemplate, fallbackSlug);
    const fields = (page as any)?.[fieldName];
    if (!fields || !hasData(fields)) return null;
    return {
      heading: fields.heading || undefined,
      bodyContent: fields.bodyContent || undefined,
      seoMetadata: transformSeoData(page?.seo || null),
    };
  } catch (error) {
    console.error(`[WP] Failed to fetch ${wpTemplate} ACF:`, error);
    return null;
  }
}

export const fetchPrivacyPolicyAcf = cache(async (): Promise<LegalPageTemplateData | null> => {
  return fetchLegalPageAcf('template-privacy-policy', 'privacy-policy', 'privacyFields');
});

export const fetchTermsOfServiceAcf = cache(async (): Promise<LegalPageTemplateData | null> => {
  return fetchLegalPageAcf('template-terms-of-service', 'terms-of-service', 'termsFields');
});

export const fetchGlobalSections = cache(async (): Promise<GlobalSectionsData | null> => {
  const client = getWpClient();
  try {
    const response = await client.request<{ trGlobalSections: Record<string, any> | null }>(
      GET_GLOBAL_SECTIONS_QUERY
    );
    const gs = response.trGlobalSections;
    if (!gs) return null;

    const p = gs.gsProcess;
    const s = gs.gsStats;
    const cb = gs.gsCtaBanner;
    const r = gs.gsReasons;
    const fc = gs.gsFinalCta;
    const loc = gs.gsLocation;
    const faq = gs.gsFaq;
    const wh = gs.gsWhoHelp;
    const lr = gs.gsLogoReel;
    const t = gs.gsTestimonials;

    return {
      process: p ? {
        tagline: p.processTagline || undefined,
        heading: p.processHeading || undefined,
        subtitle: p.processSubtitle || undefined,
        steps: nonEmpty(p.processSteps),
      } : undefined,
      stats: s ? {
        tagline: s.statsTagline || undefined,
        heading: s.statsHeading || undefined,
        subtitle: s.statsSubtitle || undefined,
        ctaLabel: s.statsCtaLabel || undefined,
        ctaLink: s.statsCtaLink || undefined,
        phoneLabel: s.statsPhoneLabel || undefined,
        phoneLink: s.statsPhoneLink || undefined,
        image: s.statsImage || undefined,
        imageAlt: s.statsImageAlt || undefined,
        cards: nonEmpty(s.statsCards),
      } : undefined,
      ctaBanner: cb ? {
        tagline: cb.ctaBannerTagline || undefined,
        heading: cb.ctaBannerHeading || undefined,
        subtitle: cb.ctaBannerSubtitle || undefined,
        placeholder: cb.ctaBannerPlaceholder || undefined,
        button: cb.ctaBannerButton || undefined,
      } : undefined,
      reasons: r ? {
        tagline: r.reasonsTagline || undefined,
        heading: r.reasonsHeading || undefined,
        subtitle: r.reasonsSubtitle || undefined,
        ctaLabel: r.reasonsCtaLabel || undefined,
        ctaLink: r.reasonsCtaLink || undefined,
        features: nonEmpty(r.reasonsFeatures),
      } : undefined,
      finalCta: fc ? {
        heading: fc.finalCtaHeading || undefined,
        subtitle: fc.finalCtaSubtitle || undefined,
        label: fc.finalCtaLabel || undefined,
        link: fc.finalCtaLink || undefined,
        image: fc.finalCtaImage || undefined,
        imageAlt: fc.finalCtaImageAlt || undefined,
        phone: fc.finalCtaPhone || undefined,
        phoneLink: fc.finalCtaPhoneLink || undefined,
      } : undefined,
      location: loc ? {
        heading: loc.locationHeading || undefined,
        subtitle: loc.locationSubtitle || undefined,
        address: loc.locationAddress || undefined,
        addressLink: loc.locationAddressLink || undefined,
        phoneNote: loc.locationPhoneNote || undefined,
        phone: loc.locationPhone || undefined,
        phoneLink: loc.locationPhoneLink || undefined,
        email: loc.locationEmail || undefined,
        emailLink: loc.locationEmailLink || undefined,
      } : undefined,
      faq: faq ? {
        tagline: faq.faqSectionTagline || undefined,
        heading: faq.faqSectionHeading || undefined,
        subtitle: faq.faqSectionSubtitle || undefined,
        faqs: nonEmpty(faq.faqItems),
        ctaText: faq.faqSectionCtaText || undefined,
        ctaLabel: faq.faqSectionCtaLabel || undefined,
        ctaLink: faq.faqSectionCtaLink || undefined,
      } : undefined,
      whoHelp: wh ? {
        tagline: wh.whoHelpTagline || undefined,
        heading: wh.whoHelpHeading || undefined,
        subtitle: wh.whoHelpSubtitle || undefined,
      } : undefined,
      logoReel: lr ? {
        headline: lr.logoReelHeadline || undefined,
      } : undefined,
      testimonials: t ? {
        tagline: t.testimonialsTagline || undefined,
      } : undefined,
    };
  } catch (error) {
    console.warn('[WP] Failed to fetch global sections (ACF options page may not be configured):', error);
    return null;
  }
});
