import { ForbiddenException, NotFoundException, Injectable, UnauthorizedException } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto, PassDto, VerifyDto } from "./dto";
import * as argon from "argon2";

import { JwtService } from '@nestjs/jwt'
import { ConfigService } from "@nestjs/config";
import { writeFileSync } from 'fs';
import { join } from "path"
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";
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
            } else if(user.phone && user.password == null) {
                delete user.creted_At
                delete user.password
                return res.status(200).json({ "status":200, "data": user })
            }

       } catch (error) {
            return res.status(500).json({ "status": 500, "message": "Internal Server Error" })
       }
    }

    async checkSms (dto:VerifyDto, res:Response):Promise<Response>{
        try {
            let check = await this.prisma.checkSms.findMany({where: {verify: dto.verify}})

            if(!check.length) {
                return res.status(400).json({ "status": 400, "message": 'The verification code is incorrect' })
            }

            if(dto.smsCode == check[0].code && check[0].count > 0){
                let user = await this.prisma.user.create({ 
                    data:{
                        phone: check[0]?.phone
                    }
                })
                await this.prisma.checkSms.updateMany({ 
                    where: {
                        phone:check[0]?.phone
                    },
                    data:{
                        count: 3
                    }
                })
                delete user.password
                delete user.creted_At
                return res.status(201).json({ "status":201, "data": user })

            } else if(check[0].count > 0){
                let count = check[0].count - 1

                await this.prisma.checkSms.updateMany({
                    where: {
                        verify: dto.verify
                    },
                    data: {
                        count: count
                    }
                })
                return res.status(400).json({"status": 400, "message": "The code entered is incorrect"})          
            } else {
                await this.prisma.checkSms.deleteMany({
                    where: {
                        verify:dto.verify
                    }
                })
                return res.status(401).json({ status: 401, message: 'If you are not registered, try again' })
            }
        } catch (error) {
            return res.status(500).json({ status: 500, message: "Internal Server Error" })
        }
    }

    async passwd(dto: PassDto, res:Response): Promise<Response>{
        try {
            let user = await this.prisma.user.findFirst({ where: { uuid: dto.uuid } })
            let check = await this.prisma.checkSms.findFirst({ where: { phone: user.phone }})
            
            if(!user) {
                return res.status(400).json({ "status": 400, "message": 'User not found' })
            } else if(user.password) {

                const password = await argon.verify(user.password, dto.password);
                if(!password) return res.status(401).json({"status": 401, "message": "Wrong password"})

                let smsCode = Math.random() * 1000000 | 0
                let verify =  Math.random() * 1000000 | 0

                writeFileSync('code.txt', `${smsCode}`)

                await this.prisma.checkSms.create({ 
                    data:{
                        verify: `${verify}`,
                        code: `${smsCode}`, 
                        phone: user[0].phone
                    }
                })

                return  res.status(201).json({
                    "phone": "+998 " + user.phone.slice(8).padStart(9, "*"),
                    "verify": `${verify}`
                })
            } else if(user.password == null) {

                const hash = await argon.hash(dto.password)
                this.prisma.user.updateMany({ where:{ phone: user.phone }, data:{ password: hash } })
                await this.prisma.checkSms.deleteMany({
                    where: {
                        phone: check.phone
                    }
                })

                return res.status(201).json(await this.signToken(user.uuid, user.phone))
            }

        } catch (error) {
            return res.status(500).json({"status": 500, "message": "Internal Server Error"})
        }
    }

    async signToken (uuid: string, phone: string): Promise<{ access_token: string }> {
        
        const payload = {
            uuid,
            phone
        }

        const secret = this.config.get('SECRET_KEY')

        const token = await this.jwt.signAsync(payload,{
            expiresIn: '15h',
            secret: secret
        })

        return { 
            access_token: token,
        }
    }
}