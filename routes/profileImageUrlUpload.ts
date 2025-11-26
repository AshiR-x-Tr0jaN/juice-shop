
import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      try {
        const url = new URL(req.body.imageUrl)

        // ✅ Whitelist protocols
        const allowedProtocols = ['http:', 'https:']
        if (!allowedProtocols.includes(url.protocol)) {
          res.status(400).send('INVALID_URL_PROTOCOL')
          return
        }

        // ✅ Whitelist domains (replace with your trusted domains)
        const allowedDomains = ['trustedsite.com', 'cdn.trustedsite.com']
        if (!allowedDomains.includes(url.hostname)) {
          res.status(400).send('INVALID_URL_DOMAIN')
          return
        }

        const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
        if (!loggedInUser) {
          next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
          return
        }

        // Fetch the image safely
        const response = await fetch(url.toString())
        if (!response.ok || !response.body) {
          throw new Error('URL returned a non-OK status code or empty body')
        }

        // Determine file extension
        const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.pathname.split('.').pop()?.toLowerCase() || '')
          ? url.pathname.split('.').pop()!.toLowerCase()
          : 'jpg'

        const filePath = `frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`
        const fileStream = fs.createWriteStream(filePath, { flags: 'w' })
        await finished(Readable.fromWeb(response.body as any).pipe(fileStream))

        const user = await UserModel.findByPk(loggedInUser.data.id)
        await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })

      } catch (error) {
        logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}`)
        res.status(400).send('FAILED_TO_UPLOAD_IMAGE')
        return
      }
    }

    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
