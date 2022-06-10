import { Body, Controller, Get, Post, UploadedFile,UseInterceptors, Res, Req } from "@nestjs/common";
import { ApiBody, ApiCreatedResponse, ApiConsumes, ApiOkResponse } from "@nestjs/swagger";
import { FileInterceptor } from "@nestjs/platform-express";
import { AuthDto, PassDto, VerifyDto } from "./dto";

import { AuthService } from "./auth.service";
import { Response, Request } from 'express'
import { ConfigService } from "@nestjs/config"
import * as crypto from 'crypto';
import { join } from "path";
import { readFileSync, writeFileSync } from "fs";

@Controller('auth')

export class AuthController {
    constructor(private authService: AuthService, private config: ConfigService){}

    @Get('getPublic')
    @ApiOkResponse({description: "Get public key"})
    getPublic():object{
        // сервер отправляет publicKey клиенту
        let key = this.config.get('PUBLIC_KEY')
        let public_key = key.split('-----')[2]
        return { public_key }
    }


    // auth/login 
    @Post('login')
    @ApiOkResponse({description: "User login"})
    @ApiConsumes('multipart/form-data')
    @ApiBody({ type: AuthDto })
    @UseInterceptors(FileInterceptor('file'))
    async login(@UploadedFile() file:any, @Body() dto: AuthDto, @Res() res: Response, @Req() req:Request ){

        // сохраняет clientPublic, отправленный клиентом
        this.rsaVerify(dto, req.headers?.sign)
        return await this.authService.login(dto, res)
    }

    // auth/checkSms 
    @Post('checkSms')
    @ApiOkResponse({description: "User login"})
    @ApiConsumes('multipart/form-data')
    @ApiBody({ type: VerifyDto })
    @UseInterceptors(FileInterceptor('file'))
    async checkSms(@UploadedFile() file:any, @Body() dto: VerifyDto, @Res() res: Response, @Req() req:Request  ){
        
        // проверяет, что отправленные данные соответствуют зашифрованным данным
        let check = await this.rsaVerify(dto, req.headers?.sign)
        if (!check) return res.status(403).json({'status': 403, 'error':'Зашифрованные данные несовместимы'})

        return await this.authService.checkSms(dto, res)
    }

    // auth/sendPassword 
    @Post('sendPassword')
    @ApiOkResponse({description: "User password"})
    @ApiConsumes('multipart/form-data')
    @ApiBody({ type: PassDto })
    @UseInterceptors(FileInterceptor('file'))
    async passwd(@UploadedFile() file:any, @Body() dto: PassDto, @Res() res: Response, @Req() req:Request ){
        
        // проверяет, что отправленные данные соответствуют зашифрованным данным
        let check = await this.rsaVerify(dto, req.headers?.sign)
        if (!check) return res.status(403).json({'status': 403, 'error':'Зашифрованные данные несовместимы'})

        return await this.authService.passwd(dto, res)
    }

    // auth/resendSms 
    @Post('resendSms')
    @ApiOkResponse({description: "Resend sms code"})
    @ApiConsumes('multipart/form-data')
    @ApiBody({ type: AuthDto })
    @UseInterceptors(FileInterceptor('file'))
    async resend(@UploadedFile() file:any, @Body() dto: AuthDto, @Res() res: Response, @Req() req:Request ){
        
        // проверяет, что отправленные данные соответствуют зашифрованным данным
        let check = await this.rsaVerify(dto, req.headers?.sign)
        if (!check) return res.status(403).json({'status': 403, 'error':'Зашифрованные данные несовместимы'})

        return await this.authService.login(dto, res)
    }

    rsaVerify(dto:any, sign){
        if ( dto.cientPublic ) { // если клиент отправил publicKey

            let publicKey = '-----BEGIN PUBLIC KEY-----\n'+dto.cientPublic+'\n-----END PUBLIC KEY-----'

            // сохраняет публичный ключ клиента в src/key/public.key
            writeFileSync('src/key/public.key', publicKey)
        } else {
            let publicKey = readFileSync('src/key/public.key', 'utf-8')

            const isVerified = crypto.verify(
                "SHA256",
               Buffer.from(JSON.stringify(dto)),
                {
                  key: publicKey,
                },
                Buffer.from(sign, 'base64')
              );
              return isVerified
        }

    }
    
}
