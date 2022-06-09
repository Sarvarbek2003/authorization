import { Injectable} from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto, PassDto, VerifyDto } from "./dto";
import * as argon from "argon2";

import { JwtService } from '@nestjs/jwt'
import { ConfigService } from "@nestjs/config";
import { writeFileSync } from 'fs';
import { Response } from "express";


@Injectable({})
export class AuthService {
    constructor(
        private prisma: PrismaService, 
        private jwt: JwtService,
        private config: ConfigService
        ){}
    
    async login (dto: AuthDto, res:Response):Promise<Response>{
       try {
            const user = await this.prisma.user.findFirst({
                where: {
                    phone :dto.phone
                }
            });
            if(!user) {
                let kluch = await this.sendSmsTime(dto)

                if(!kluch) return res.status(302).json({"status": 302, "message": "Если вы уже получили смс-код, а смс не приходит в течение 5 минут, попробуйте еще раз" })

                let smsCode = Math.random() * 1000000 | 0
                let verify =  Math.random() * 1000000 | 0

                writeFileSync('code.txt', `${smsCode}`)

                await this.prisma.checkSms.create({ 
                    data:{
                        verify: `${verify}`,
                        code: `${smsCode}`, 
                        phone: dto.phone
                    }
                })
                
                return  res.status(201).json({
                    "phone": "+998 " + dto.phone.slice(8).padStart(9, "*"),
                    "verify": `${verify}`
                })
            } else if(user.phone) {
                delete user.creted_At
                delete user.password
                return res.status(200).json({ "status":200, "data": user })
            }

       } catch (error) {
            return res.status(500).json({ "status": 500, "error": "Internal Server Error" })
       }
    }

    async checkSms (dto:VerifyDto, res:Response):Promise<Response>{
        try {
            let check = await this.prisma.checkSms.findMany({where: {verify: dto.verify}})

            if( !check.length ) {
                return res.status(400).json({ "status": 400, "error": 'Код подтверждения неверный' })
            }

            let user = await this.prisma.user.findFirst({ where:{ phone: check[0].phone } })

            if(dto.smsCode == check[0].code && check[0].count >  0){
                if(!user?.password){
                    let user = await this.prisma.user.create({ 
                        data:{
                            phone: check[0]?.phone
                        }
                    })
                    delete user.password
                    delete user.creted_At
                    return res.status(201).json({ "status":201, "data": user })
                } else {
                    await this.prisma.checkSms.deleteMany({ 
                        where: {
                            phone:check[0]?.phone
                        }
                    })
                    return res.status(201).json(await this.signToken(user.uuid, user.phone))
                }                
            } else if ( check[0].count > 0 ){
                let count = check[0].count - 1

                await this.prisma.checkSms.updateMany({
                    where: {
                        verify: dto.verify
                    },
                    data: {
                        count: count
                    }
                })
                return res.status(400).json({"status": 400, "error": "Код подтверждения неверный"})          
            } else {
                await this.prisma.checkSms.deleteMany({
                    where: {
                        verify:dto.verify
                    }
                })
                return res.status(401).json({ "status": 401, "error": 'Регистрация не удалась, попробуйте позже' })
            }
        } catch (error) {
            return res.status(500).json({ "status": 500, "error": "Internal Server Error" })
        }
    }

    async passwd(dto: PassDto, res:Response): Promise<Response>{
        try {
            let user = await this.prisma.user.findFirst({ where: { uuid: dto.uuid } })
            let check = await this.prisma.checkSms.findFirst({ where: { phone: user.phone }})
            if(!user) {
                return res.status(400).json({ "status": 400, "error": 'Пользователь не найден' })
            } else if(user.password) {

                const password = await argon.verify(user.password, dto.password);
                if(!password) return res.status(401).json({"status": 401, "error": "Пароль неверен"})

                let kluch = await this.sendSmsTime(user.phone)
                if(!kluch) return res.status(302).json({"status": 302, "message": "Если вы уже получили смс-код, а смс не приходит в течение 5 минут, попробуйте еще раз" })

                let smsCode = Math.random() * 1000000 | 0
                let verify =  Math.random() * 1000000 | 0

                writeFileSync('code.txt', `${smsCode}`)

                await this.prisma.checkSms.create({ 
                    data:{
                        verify: `${verify}`,
                        code: `${smsCode}`, 
                        phone: user.phone
                    }
                })

                return  res.status(201).json({
                    "phone": "+998 " + user.phone.slice(8).padStart(9, "*"),
                    "verify": `${verify}`
                })
            } else if(user.password == null) {

                const hash = await argon.hash(dto.password)
                let a = await this.prisma.user.updateMany({ where:{ phone: user.phone }, data:{ password: hash } })
                await this.prisma.checkSms.deleteMany({
                    where: {
                        phone: check.phone
                    }
                })

                return res.status(201).json(await this.signToken(user.uuid, user.phone))
            }

        } catch (error) {
            return res.status(500).json({"status": 500, "error": "Internal Server Error"})
        }
    }

    async sendSmsTime(dto): Promise<Boolean>{
        let check = await this.prisma.checkSms.findFirst({ where: { phone: dto.phone } })
        if ( !check ) return true
        else {
            let check_date = check.creted_At 
            let date1 = new Date().getTime()
            let date2 = new Date(check_date).getTime()
            if( (date1 - date2) >= 300000 ) {
                await this.prisma.checkSms.deleteMany({ where: { phone: dto.phone } })
                return true 
            } else {
                return false 
            }
        }
    }

    async signToken (uuid: string, phone: string): Promise<{ access_token: string }> {

        const payload = {
            uuid,
            phone
        }

        const secret = this.config.get('SECRET_KEY')
        const expiresIn = this.config.get('EXPIRESIN')

        const token = await this.jwt.signAsync(payload,{
            expiresIn,
            secret
        })

        return { 
            access_token: token,
        }
    }
}