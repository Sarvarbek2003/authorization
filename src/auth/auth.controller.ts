import { Body, Controller, Post, Res } from "@nestjs/common";
import { Response } from 'express'
import { AuthService } from "./auth.service";
import { AuthDto, PassDto, VerifyDto } from "./dto";
import { ApiBody, ApiCreatedResponse, ApiConsumes, ApiOkResponse, ApiUnauthorizedResponse } from "@nestjs/swagger";



@Controller('auth')

export class AuthController {
    constructor(private authService: AuthService){}

    @Post('login')
    @ApiOkResponse({description: "User login"})
    @ApiBody({ type: AuthDto })
    async login(@Body() dto: AuthDto, @Res() res: Response ){
        return await this.authService.login(dto, res)
    }

    @Post('checkSms')
    @ApiOkResponse({description: "User login"})
    @ApiBody({ type: VerifyDto })
    async checkSms(@Body() dto: VerifyDto, @Res() res: Response  ){
        return await this.authService.checkSms(dto, res)
    }

    @Post('passwd')
    @ApiOkResponse({description: "User password"})
    @ApiBody({ type: PassDto })
    async passwd(@Body() dto: PassDto, @Res() res: Response ){
        return await this.authService.passwd(dto, res)
    }

    @Post('resend')
    @ApiOkResponse({description: "Resend sms code"})
    @ApiBody({ type: AuthDto })
    async resend(@Body() dto: AuthDto, @Res() res: Response ){
        return await this.authService.login(dto, res)
    }
    
}