import { ExtensionsProps as GenericExtensionsProps } from '@sourcegraph/extensions-client-common/lib/context'
import { Controller as ExtensionsContextController } from '@sourcegraph/extensions-client-common/lib/controller'
import { CXPControllerProps as GenericCXPControllerProps } from '@sourcegraph/extensions-client-common/lib/cxp/controller'
import { ConfiguredExtension } from '@sourcegraph/extensions-client-common/lib/extensions/extension'
import { QueryResult } from '@sourcegraph/extensions-client-common/lib/graphql'
import * as ECCGQL from '@sourcegraph/extensions-client-common/lib/schema/graphqlschema'
import {
    ConfigurationCascadeProps as GenericConfigurationCascadeProps,
    ConfigurationSubject,
    gqlToCascade,
    Settings,
} from '@sourcegraph/extensions-client-common/lib/settings'
import CaretDown from '@sourcegraph/icons/lib/CaretDown'
import Loader from '@sourcegraph/icons/lib/Loader'
import Menu from '@sourcegraph/icons/lib/Menu'
import Warning from '@sourcegraph/icons/lib/Warning'
import { ClientOptions } from 'cxp/module/client/client'
import { MessageTransports } from 'cxp/module/jsonrpc2/connection'
import { createWebWorkerMessageTransports } from 'cxp/module/jsonrpc2/transports/webWorker'
import { ConfigurationUpdateParams } from 'cxp/module/protocol'
import { isEqual } from 'lodash'
import { concat, Observable } from 'rxjs'
import { distinctUntilChanged, map, switchMap, take } from 'rxjs/operators'
import { gql, queryGraphQL } from '../backend/graphql'
import * as GQL from '../backend/graphqlschema'
import { Tooltip } from '../components/tooltip/Tooltip'
import { editConfiguration } from '../configuration/backend'
import { configurationCascade, toGQLKeyPath } from '../settings/configuration'
import { refreshConfiguration } from '../user/settings/backend'
import { isErrorLike } from '../util/errors'

export interface CXPControllerProps extends GenericCXPControllerProps<ConfigurationSubject, Settings> {}

export interface ConfigurationCascadeProps extends GenericConfigurationCascadeProps<ConfigurationSubject, Settings> {}

export interface ExtensionsProps extends GenericExtensionsProps<ConfigurationSubject, Settings> {}

export function createExtensionsContextController(): ExtensionsContextController<ConfigurationSubject, Settings> {
    return new ExtensionsContextController<ConfigurationSubject, Settings>({
        configurationCascade: configurationCascade.pipe(
            map(gqlToCascade),
            distinctUntilChanged((a, b) => isEqual(a, b))
        ),
        updateExtensionSettings,
        queryGraphQL: (request, variables) =>
            queryGraphQL(
                gql`
                    ${request}
                `,
                variables
            ) as Observable<QueryResult<Pick<ECCGQL.IQuery, 'extensionRegistry'>>>,
        icons: {
            Loader: Loader as React.ComponentType<{ className: string; onClick?: () => void }>,
            Warning: Warning as React.ComponentType<{ className: string; onClick?: () => void }>,
            CaretDown: CaretDown as React.ComponentType<{ className: string; onClick?: () => void }>,
            Menu: Menu as React.ComponentType<{ className: string; onClick?: () => void }>,
        },
        forceUpdateTooltip: () => Tooltip.forceUpdate(),
    })
}

function updateExtensionSettings(
    subject: string,
    args: {
        extensionID: string
        edit?: ConfigurationUpdateParams
        enabled?: boolean
        remove?: boolean
    }
): Observable<void> {
    return configurationCascade.pipe(
        take(1),
        switchMap(configurationCascade => {
            const subjectConfig = configurationCascade.subjects.find(s => s.id === subject)
            if (!subjectConfig) {
                throw new Error(`no configuration subject: ${subject}`)
            }
            const lastID = subjectConfig.latestSettings ? subjectConfig.latestSettings.id : null

            let edit: GQL.IConfigurationEdit
            if (args.edit) {
                edit = { keyPath: toGQLKeyPath(args.edit.path), value: args.edit.value }
            } else if (typeof args.enabled === 'boolean') {
                edit = { keyPath: toGQLKeyPath(['extensions', args.extensionID]), value: args.enabled }
            } else if (args.remove) {
                edit = { keyPath: toGQLKeyPath(['extensions', args.extensionID]), value: null }
            } else {
                throw new Error('no edit')
            }
            return editConfiguration(subject, lastID, edit)
        }),
        switchMap(() => concat(refreshConfiguration(), [void 0]))
    )
}

export function updateUserExtensionSettings(args: { extensionID: string; enabled?: boolean }): Observable<void> {
    return configurationCascade.pipe(
        take(1),
        switchMap(configurationCascade => {
            // Only support configuring extension settings in user settings with this action.
            const subject = configurationCascade.subjects[configurationCascade.subjects.length - 1]
            return updateExtensionSettings(subject.id, args)
        })
    )
}

export function createMessageTransports(
    extension: Pick<ConfiguredExtension, 'id' | 'manifest'>,
    options: ClientOptions
): Promise<MessageTransports> {
    if (!extension.manifest) {
        throw new Error(`unable to run extension ${JSON.stringify(extension.id)}: no manifest found`)
    }
    if (isErrorLike(extension.manifest)) {
        throw new Error(
            `unable to run extension ${JSON.stringify(extension.id)}: invalid manifest: ${extension.manifest.message}`
        )
    }
    if (extension.manifest.url) {
        const url = extension.manifest.url
        return fetch(url)
            .then(resp => {
                if (resp.status !== 200) {
                    return resp
                        .text()
                        .then(text => Promise.reject(new Error(`loading bundle from ${url} failed: ${text}`)))
                }
                return resp.text()
            })
            .then(bundleSource => {
                const blobURL = window.URL.createObjectURL(
                    new Blob([bundleSource], {
                        type: 'application/javascript',
                    })
                )
                const worker = new Worker(blobURL)
                return createWebWorkerMessageTransports(worker)
            })
    }
    throw new Error(`unable to run extension ${JSON.stringify(extension.id)}: no "url" property in manifest`)
}